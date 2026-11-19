package apiv2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

// federationHTTPTimeout bounds each fetch of an issuer's discovery document or keys.
const federationHTTPTimeout = 10 * time.Second

// registerTokenExchange mounts POST /api/v2/oauth/token-exchange, which trades an issuer's OIDC token for an access token.
func registerTokenExchange(router chi.Router, b Backend) {
	ex := &tokenExchange{b: b}
	router.Post("/api/v2/oauth/token-exchange", ex.handle)
}

type tokenExchange struct {
	b Backend
}

// issuerRefetchInterval is the least time between fetches of one issuer's discovery document, or of its keys.
const issuerRefetchInterval = time.Minute

// issuerCacheMaxAge is how long an issuer's discovery document and keys are used before they are fetched again.
const issuerCacheMaxAge = 15 * time.Minute

// maxIssuerResponseBytes caps each discovery document or key set read from an issuer.
const maxIssuerResponseBytes = 1 << 20

var (
	errSignatureInvalid       = errors.New("no issuer key verifies the token signature")
	errJWKSFetch              = errors.New("fetching issuer keys")
	errIssuerResponseTooLarge = errors.New("issuer response too large")
	errIssuerUnavailable      = errors.New("issuer unavailable")
)

// limitResponses returns a copy of client whose response bodies fail once longer than maxIssuerResponseBytes.
func limitResponses(client *http.Client) *http.Client {
	limited := *client

	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}

	limited.Transport = limitedTransport{base: base}

	return &limited
}

type limitedTransport struct {
	base http.RoundTripper
}

func (t limitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	resp.Body = &limitedBody{ReadCloser: resp.Body, left: maxIssuerResponseBytes}

	return resp, nil
}

type limitedBody struct {
	io.ReadCloser

	left int64
}

func (b *limitedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, errIssuerResponseTooLarge
	}

	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}

	n, err := b.ReadCloser.Read(p)

	b.left -= int64(n)
	if b.left < 0 {
		return n + int(b.left), errIssuerResponseTooLarge
	}

	return n, err
}

// signingAlgs are the JWS algorithms an issuer may sign with.
var signingAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.EdDSA,
}

// issuerVerifiers caches each issuer's discovered signing setup for maxAge, or until an identity using it is updated or deleted.
type issuerVerifiers struct {
	client     *http.Client
	minRefetch time.Duration
	maxAge     time.Duration

	mu      sync.Mutex
	issuers map[string]*issuerVerifier
}

// issuerVerifier is one issuer's signing setup and the error of its last discovery.
type issuerVerifier struct {
	mu         sync.Mutex
	signing    *issuerSigning
	discovered time.Time
	tried      time.Time
	err        error
}

// issuerSigning is an issuer's keys and the algorithms it signs tokens with.
type issuerSigning struct {
	issuer string
	keys   *issuerKeys
	algs   []string
}

// verify checks jwt's signature, issuer and expiry, reporting a failure to reach the issuer as such.
func (s *issuerSigning) verify(ctx context.Context, jwt string) (*oidc.IDToken, error) {
	keys := &recordingKeySet{keys: s.keys}

	idToken, err := oidc.NewVerifier(s.issuer, keys, &oidc.Config{SkipClientIDCheck: true, SupportedSigningAlgs: s.algs}).
		Verify(ctx, jwt)
	if err != nil && keys.err != nil {
		return nil, keys.err
	}

	return idToken, err
}

// recordingKeySet keeps the error of its keys, which go-oidc returns only as text.
type recordingKeySet struct {
	keys *issuerKeys
	err  error
}

func (r *recordingKeySet) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	payload, err := r.keys.VerifySignature(ctx, jwt)
	r.err = err

	return payload, err
}

func newIssuerVerifiers(client *http.Client) *issuerVerifiers {
	if client == nil {
		client = &http.Client{Timeout: federationHTTPTimeout}
	}

	return &issuerVerifiers{
		client:     limitResponses(client),
		minRefetch: issuerRefetchInterval,
		maxAge:     issuerCacheMaxAge,
		issuers:    map[string]*issuerVerifier{},
	}
}

// get returns issuer's signing setup, discovering it again after maxAge, one discovery at a time and at most once per minRefetch; a failed rediscovery keeps the old setup.
func (iv *issuerVerifiers) get(issuer string) (*issuerSigning, error) {
	iv.mu.Lock()

	entry, ok := iv.issuers[issuer]
	if !ok {
		entry = &issuerVerifier{}
		iv.issuers[issuer] = entry
	}

	iv.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	if entry.signing != nil && time.Since(entry.discovered) < iv.maxAge {
		return entry.signing, nil
	}

	if time.Since(entry.tried) >= iv.minRefetch {
		entry.tried = time.Now()

		signing, err := iv.discover(issuer, entry.signing)
		if err == nil {
			entry.signing, entry.discovered = signing, entry.tried
		}

		entry.err = err
	}

	if entry.signing != nil {
		return entry.signing, nil
	}

	return nil, entry.err
}

// discover fetches issuer's discovery document, keeping prev's keys if the key URL is unchanged.
func (iv *issuerVerifiers) discover(issuer string, prev *issuerSigning) (*issuerSigning, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(context.Background(), iv.client), issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerUnavailable, err)
	}

	var meta struct {
		JWKSURL string   `json:"jwks_uri"`
		Algs    []string `json:"id_token_signing_alg_values_supported"`
	}

	err = provider.Claims(&meta)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errIssuerUnavailable, err)
	}

	var algs []string

	for _, alg := range meta.Algs {
		if slices.Contains(signingAlgs, jose.SignatureAlgorithm(alg)) {
			algs = append(algs, alg)
		}
	}

	if prev != nil && prev.keys.url == meta.JWKSURL {
		return &issuerSigning{issuer: issuer, keys: prev.keys, algs: algs}, nil
	}

	keys := &issuerKeys{client: iv.client, url: meta.JWKSURL, minRefetch: iv.minRefetch, maxAge: iv.maxAge}

	return &issuerSigning{issuer: issuer, keys: keys, algs: algs}, nil
}

func (iv *issuerVerifiers) forget(issuer string) {
	if iv == nil {
		return
	}

	iv.mu.Lock()
	delete(iv.issuers, issuer)
	iv.mu.Unlock()
}

// issuerKeys holds an issuer's signing keys, fetched again after maxAge or when no key verifies a token, one fetch at a time and at most once per minRefetch.
type issuerKeys struct {
	client     *http.Client
	url        string
	minRefetch time.Duration
	maxAge     time.Duration

	fetchMu sync.Mutex
	fetched time.Time

	mu        sync.RWMutex
	keys      []jose.JSONWebKey
	refreshed time.Time
}

func (ik *issuerKeys) VerifySignature(ctx context.Context, jwt string) ([]byte, error) {
	jws, err := jose.ParseSignedCompact(jwt, signingAlgs)
	if err != nil {
		return nil, err
	}

	keys, refreshed := ik.cached()
	if time.Since(refreshed) < ik.maxAge {
		payload, ok := verifyWithKeys(jws, keys)
		if ok {
			return payload, nil
		}
	}

	keys, err = ik.refetch(context.WithoutCancel(ctx))

	payload, ok := verifyWithKeys(jws, keys)
	if ok {
		return payload, nil
	}

	if err != nil {
		return nil, err
	}

	return nil, errSignatureInvalid
}

func (ik *issuerKeys) cached() ([]jose.JSONWebKey, time.Time) {
	ik.mu.RLock()
	defer ik.mu.RUnlock()

	return ik.keys, ik.refreshed
}

// refetch fetches the keys unless a fetch started within minRefetch, returning the keys held afterwards; a failed fetch keeps the old keys.
func (ik *issuerKeys) refetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	ik.fetchMu.Lock()
	defer ik.fetchMu.Unlock()

	if time.Since(ik.fetched) < ik.minRefetch {
		keys, _ := ik.cached()

		return keys, nil
	}

	ik.fetched = time.Now()

	keys, err := ik.fetch(ctx)
	if err != nil {
		old, _ := ik.cached()

		return old, fmt.Errorf("%w: %w", errIssuerUnavailable, err)
	}

	ik.mu.Lock()
	ik.keys, ik.refreshed = keys, ik.fetched
	ik.mu.Unlock()

	return keys, nil
}

// fetch reads the issuer's JWKS, skipping keys go-jose cannot use, as RFC 7517 section 5 asks.
func (ik *issuerKeys) fetch(ctx context.Context) ([]jose.JSONWebKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ik.url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := ik.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s: %s", errJWKSFetch, ik.url, resp.Status)
	}

	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}

	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", ik.url, err)
	}

	keys := make([]jose.JSONWebKey, 0, len(set.Keys))

	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		if json.Unmarshal(raw, &key) == nil {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// verifyWithKeys verifies jws against the keys whose id matches its key id, or all keys when it names none.
func verifyWithKeys(jws *jose.JSONWebSignature, keys []jose.JSONWebKey) ([]byte, bool) {
	kid := jws.Signatures[0].Header.KeyID

	for _, key := range keys {
		if kid != "" && key.KeyID != kid {
			continue
		}

		payload, err := jws.Verify(&key)
		if err == nil {
			return payload, true
		}
	}

	return nil, false
}

func (ex *tokenExchange) handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxTokenRequestBytes)

	err := r.ParseForm()
	if err != nil {
		writeInvalidRequest(w)

		return
	}

	fi, err := ex.b.State.GetFederatedIdentity(r.PostForm.Get("client_id"))

	switch {
	case errors.Is(err, db.ErrFederatedIdentityNotFound):
		writeInvalidRequest(w)

		return
	case err != nil:
		writeMessage(w, http.StatusInternalServerError, "could not mint access token")

		return
	}

	jwt := r.PostForm.Get("jwt")
	if jwt == "" {
		writeMessage(w, http.StatusBadRequest, "request must include a jwt")

		return
	}

	idToken, claims, err := ex.verify(r.Context(), fi, jwt)

	switch {
	case errors.Is(err, errIssuerUnavailable):
		log.Error().Str("federated_identity", fi.ClientID).Str("issuer", fi.Issuer).Err(err).Msg("token exchange failed: issuer unavailable")
		writeMessage(w, http.StatusBadGateway, "could not reach the token issuer")

		return
	case err != nil:
		writeRefused(w, fi.ClientID, err)

		return
	}

	expiry := time.Now().Add(accessTokenTTL)

	tokenStr, token, err := ex.b.State.ExchangeFederatedToken(fi.ClientID, func(cur *types.FederatedIdentity) error {
		return admitClaims(cur, idToken, claims)
	}, &expiry)

	switch {
	case errors.Is(err, db.ErrFederatedExchangeRefused), errors.Is(err, db.ErrFederatedIdentityNotFound):
		writeRefused(w, fi.ClientID, err)

		return
	case err != nil:
		writeMessage(w, http.StatusInternalServerError, "could not mint access token")

		return
	}

	resp := tokenResponse{
		AccessToken: tokenStr,
		TokenType:   "Bearer",
		ExpiresIn:   int(accessTokenTTL.Seconds()),
		Scope:       strings.Join(token.Scopes, " "),
	}

	if tokenCanAssignTags(scope.Parse(token.Scopes)) {
		resp.Tags = strings.Join(token.Tags, " ")
	}

	writeJSON(w, http.StatusOK, resp)
}

func writeRefused(w http.ResponseWriter, clientID string, err error) {
	log.Info().Str("federated_identity", clientID).Err(err).Msg("token exchange refused")
	writeMessage(w, http.StatusForbidden, "Unauthorized")
}

// verify checks jwt's signature, issuer and expiry against fi's issuer and returns its claims.
func (ex *tokenExchange) verify(ctx context.Context, fi *types.FederatedIdentity, jwt string) (*oidc.IDToken, map[string]any, error) {
	signing, err := ex.b.verifiers.get(fi.Issuer) //nolint:contextcheck // The cached setup outlives the request.
	if err != nil {
		return nil, nil, err
	}

	idToken, err := signing.verify(ctx, jwt)
	if err != nil {
		return nil, nil, err
	}

	var raw json.RawMessage

	err = idToken.Claims(&raw)
	if err != nil {
		return nil, nil, err
	}

	claims, err := decodeClaims(raw)
	if err != nil {
		return nil, nil, err
	}

	return idToken, claims, nil
}

// decodeClaims decodes a token's claims, keeping numbers as written so large integers stay exact.
func decodeClaims(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()

	var claims map[string]any

	err := dec.Decode(&claims)
	if err != nil {
		return nil, err
	}

	return claims, nil
}

// admitClaims checks a verified token's issuer, audience, subject and custom claim rules against fi.
func admitClaims(fi *types.FederatedIdentity, idToken *oidc.IDToken, claims map[string]any) error {
	if idToken.Issuer != fi.Issuer {
		return claimMismatchError("iss")
	}

	if !slices.Contains(idToken.Audience, fi.Audience) {
		return claimMismatchError("aud")
	}

	if !matchPattern(fi.Subject, idToken.Subject) {
		return claimMismatchError("sub")
	}

	for path, pattern := range fi.CustomClaimRules {
		value, ok := claimString(claims, types.SplitClaimPath(path))
		if !ok || !matchPattern(pattern, value) {
			return claimMismatchError(path)
		}
	}

	return nil
}

type claimMismatchError string

func (e claimMismatchError) Error() string {
	return "claim " + strconv.Quote(string(e)) + " does not match"
}

// claimString resolves path in claims to a scalar's string form; absent claims, objects and arrays do not resolve.
func claimString(claims map[string]any, path []string) (string, bool) {
	var v any = claims

	for _, seg := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return "", false
		}

		v, ok = m[seg]
		if !ok {
			return "", false
		}
	}

	switch v := v.(type) {
	case string:
		return v, true
	case bool:
		return strconv.FormatBool(v), true
	case json.Number:
		if !strings.ContainsAny(v.String(), ".eE") {
			return v.String(), true
		}

		f, err := v.Float64()
		if err != nil {
			return "", false
		}

		return strconv.FormatFloat(f, 'f', -1, 64), true
	default:
		return "", false
	}
}

// matchPattern reports whether s matches pattern, where * matches any run of characters.
func matchPattern(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}

	if !strings.HasPrefix(s, parts[0]) {
		return false
	}

	s = s[len(parts[0]):]
	last := parts[len(parts)-1]

	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}

		s = s[i+len(part):]
	}

	return strings.HasSuffix(s, last)
}

func writeMessage(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"message": message})
}

// writeInvalidRequest answers an unknown client or unparseable request in plain text, as Tailscale does.
func writeInvalidRequest(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("invalid request\n"))
}
