package apiv2

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jwksServer serves the public halves of keys, counting fetches.
type jwksServer struct {
	srv     *httptest.Server
	fetches atomic.Int64
	fail    atomic.Bool

	mu   sync.Mutex
	keys map[string]*rsa.PrivateKey
}

func newJWKSServer(t *testing.T) *jwksServer {
	t.Helper()

	js := &jwksServer{keys: map[string]*rsa.PrivateKey{}}
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.fetches.Add(1)

		if js.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		js.mu.Lock()
		defer js.mu.Unlock()

		var set jose.JSONWebKeySet
		for kid, key := range js.keys {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.RS256), Use: "sig"})
		}

		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(js.srv.Close)

	return js
}

func (js *jwksServer) addKey(t *testing.T, kid string) *rsa.PrivateKey {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	js.mu.Lock()
	js.keys[kid] = key
	js.mu.Unlock()

	return key
}

func (js *jwksServer) keySet() *issuerKeys {
	return &issuerKeys{client: js.srv.Client(), url: js.srv.URL, minRefetch: issuerRefetchInterval, maxAge: issuerCacheMaxAge}
}

func (js *jwksServer) removeKey(kid string) {
	js.mu.Lock()
	delete(js.keys, kid)
	js.mu.Unlock()
}

// age makes ks's keys and last fetch look older than its maximum age.
func (ks *issuerKeys) age() {
	ks.fetched = ks.fetched.Add(-issuerCacheMaxAge)
	ks.refreshed = ks.refreshed.Add(-issuerCacheMaxAge)
}

func signWith(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", kid),
	)
	require.NoError(t, err)

	jws, err := signer.Sign([]byte(`{"sub":"x"}`))
	require.NoError(t, err)

	compact, err := jws.CompactSerialize()
	require.NoError(t, err)

	return compact
}

func forgedToken(t *testing.T, kid string) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	return signWith(t, key, kid)
}

func TestIssuerKeysForgedTokensDoNotRefetch(t *testing.T) {
	js := newJWKSServer(t)
	key := js.addKey(t, "a")
	ks := js.keySet()

	_, err := ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err)

	for _, kid := range []string{"a", "unknown", ""} {
		_, err = ks.VerifySignature(t.Context(), forgedToken(t, kid))
		require.ErrorIs(t, err, errSignatureInvalid)
	}

	assert.Equal(t, int64(1), js.fetches.Load())
}

func TestIssuerKeysConcurrentMissesShareOneFetch(t *testing.T) {
	js := newJWKSServer(t)
	js.addKey(t, "a")
	ks := js.keySet()

	tokens := make([]string, 20)
	for i := range tokens {
		tokens[i] = forgedToken(t, "a")
	}

	var wg sync.WaitGroup
	for _, token := range tokens {
		wg.Go(func() {
			_, err := ks.VerifySignature(context.Background(), token)
			assert.ErrorIs(t, err, errSignatureInvalid)
		})
	}

	wg.Wait()

	assert.Equal(t, int64(1), js.fetches.Load())
}

func TestIssuerKeysRotation(t *testing.T) {
	js := newJWKSServer(t)
	old := js.addKey(t, "a")
	ks := js.keySet()

	_, err := ks.VerifySignature(t.Context(), signWith(t, old, "a"))
	require.NoError(t, err)

	rotated := js.addKey(t, "b")

	_, err = ks.VerifySignature(t.Context(), signWith(t, rotated, "b"))
	require.ErrorIs(t, err, errSignatureInvalid, "a new key is not fetched within the interval")

	ks.fetched = time.Now().Add(-issuerRefetchInterval)

	_, err = ks.VerifySignature(t.Context(), signWith(t, rotated, "b"))
	require.NoError(t, err, "a new key is fetched once the interval has passed")

	_, err = ks.VerifySignature(t.Context(), signWith(t, old, "a"))
	require.NoError(t, err)

	assert.Equal(t, int64(2), js.fetches.Load())
}

func TestIssuerKeysFailedFetchIsDebounced(t *testing.T) {
	js := newJWKSServer(t)
	key := js.addKey(t, "a")
	js.fail.Store(true)
	ks := js.keySet()

	_, err := ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.Error(t, err)

	js.fail.Store(false)

	_, err = ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.ErrorIs(t, err, errSignatureInvalid)

	assert.Equal(t, int64(1), js.fetches.Load())
}

func TestIssuerKeysExpire(t *testing.T) {
	js := newJWKSServer(t)
	key := js.addKey(t, "a")
	ks := js.keySet()

	_, err := ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err)

	js.removeKey("a")

	_, err = ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err, "a removed key verifies until the cached keys expire")

	ks.age()

	_, err = ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.ErrorIs(t, err, errSignatureInvalid, "expired keys are fetched again, without the removed key")

	assert.Equal(t, int64(2), js.fetches.Load())
}

func TestIssuerKeysFailedRefreshKeepsKeys(t *testing.T) {
	js := newJWKSServer(t)
	key := js.addKey(t, "a")
	ks := js.keySet()

	_, err := ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err)

	js.fail.Store(true)
	ks.age()

	_, err = ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err, "a failed refresh keeps the expired keys")

	_, err = ks.VerifySignature(t.Context(), signWith(t, key, "a"))
	require.NoError(t, err)

	assert.Equal(t, int64(2), js.fetches.Load(), "the failed refresh is not retried within the interval")
}

func TestIssuerSigningReportsUnavailableIssuer(t *testing.T) {
	js := newJWKSServer(t)
	key := js.addKey(t, "a")
	signing := &issuerSigning{issuer: "https://issuer.example.com", keys: js.keySet(), algs: []string{string(jose.RS256)}}

	_, err := signing.verify(t.Context(), forgedToken(t, "a"))
	require.ErrorIs(t, err, errSignatureInvalid)
	require.NotErrorIs(t, err, errIssuerUnavailable, "a forged token is refused, not blamed on the issuer")

	js.fail.Store(true)
	signing.keys.age()

	_, err = signing.verify(t.Context(), signWith(t, key, "b"))
	require.ErrorIs(t, err, errIssuerUnavailable, "a key fetch that fails is the issuer's failure")
}

func TestLimitResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		_, _ = w.Write(bytes.Repeat([]byte("a"), n))
	}))
	t.Cleanup(srv.Close)

	client := limitResponses(srv.Client())

	read := func(n int) (int, error) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"?n="+strconv.Itoa(n), nil)
		require.NoError(t, err)

		resp, err := client.Do(req)
		require.NoError(t, err)

		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)

		return len(body), err
	}

	got, err := read(maxIssuerResponseBytes)
	require.NoError(t, err)
	assert.Equal(t, maxIssuerResponseBytes, got)

	got, err = read(maxIssuerResponseBytes + 1)
	require.ErrorIs(t, err, errIssuerResponseTooLarge)
	assert.Equal(t, maxIssuerResponseBytes, got)
}

func TestIssuerVerifiersOversizedDiscovery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"pad":"` + strings.Repeat("a", maxIssuerResponseBytes) + `"}`))
	}))
	t.Cleanup(srv.Close)

	_, err := newIssuerVerifiers(srv.Client()).get(srv.URL)
	require.ErrorContains(t, err, errIssuerResponseTooLarge.Error())
}

func TestClaimStringNumbers(t *testing.T) {
	claims, err := decodeClaims([]byte(`{"big":12345678901234567891,"small":42,"neg":-7,"frac":1.5,"exp":1e3}`))
	require.NoError(t, err)

	for path, want := range map[string]string{
		"big":   "12345678901234567891",
		"small": "42",
		"neg":   "-7",
		"frac":  "1.5",
		"exp":   "1000",
	} {
		got, ok := claimString(claims, []string{path})
		assert.True(t, ok, path)
		assert.Equal(t, want, got, path)
	}
}

func TestClaimStringRefusesArraysAndObjects(t *testing.T) {
	claims, err := decodeClaims([]byte(`{"groups":["alpha","beta"],"repo":{"name":"x"}}`))
	require.NoError(t, err)

	for _, path := range []string{"groups", "repo"} {
		_, ok := claimString(claims, []string{path})
		assert.False(t, ok, path)
	}
}

// discoveryServer serves an OIDC discovery document naming itself as issuer, counting fetches.
type discoveryServer struct {
	srv     *httptest.Server
	fetches atomic.Int64
	fail    atomic.Bool
}

func newDiscoveryServer(t *testing.T) *discoveryServer {
	t.Helper()

	ds := &discoveryServer{}
	ds.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ds.fetches.Add(1)

		if ds.fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                ds.srv.URL,
			"jwks_uri":                              ds.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(ds.srv.Close)

	return ds
}

func TestIssuerVerifiersConcurrentDiscoveriesShareOneFetch(t *testing.T) {
	ds := newDiscoveryServer(t)
	iv := newIssuerVerifiers(ds.srv.Client())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			_, err := iv.get(ds.srv.URL)
			assert.NoError(t, err)
		})
	}

	wg.Wait()

	assert.Equal(t, int64(1), ds.fetches.Load())
}

func TestIssuerVerifiersFailedDiscoveryIsDebounced(t *testing.T) {
	ds := newDiscoveryServer(t)
	ds.fail.Store(true)
	iv := newIssuerVerifiers(ds.srv.Client())

	_, err := iv.get(ds.srv.URL)
	require.ErrorIs(t, err, errIssuerUnavailable)

	ds.fail.Store(false)

	_, err = iv.get(ds.srv.URL)
	require.Error(t, err, "a failed discovery is not retried within the interval")
	assert.Equal(t, int64(1), ds.fetches.Load())

	iv.issuers[ds.srv.URL].tried = time.Now().Add(-issuerRefetchInterval)

	_, err = iv.get(ds.srv.URL)
	require.NoError(t, err, "discovery is retried once the interval has passed")

	_, err = iv.get(ds.srv.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(2), ds.fetches.Load())

	iv.forget(ds.srv.URL)

	_, err = iv.get(ds.srv.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(3), ds.fetches.Load(), "a forgotten issuer is discovered again")
}

func TestIssuerVerifiersExpire(t *testing.T) {
	ds := newDiscoveryServer(t)
	iv := newIssuerVerifiers(ds.srv.Client())

	first, err := iv.get(ds.srv.URL)
	require.NoError(t, err)

	entry := iv.issuers[ds.srv.URL]
	keys := entry.signing.keys
	entry.discovered = entry.discovered.Add(-issuerCacheMaxAge)
	entry.tried = entry.tried.Add(-issuerCacheMaxAge)

	second, err := iv.get(ds.srv.URL)
	require.NoError(t, err)
	assert.NotSame(t, first, second, "an expired discovery is fetched again")
	assert.Same(t, keys, entry.signing.keys, "rediscovery keeps the keys while the key URL is unchanged")
	assert.Equal(t, int64(2), ds.fetches.Load())

	ds.fail.Store(true)

	entry.discovered = entry.discovered.Add(-issuerCacheMaxAge)
	entry.tried = entry.tried.Add(-issuerCacheMaxAge)

	third, err := iv.get(ds.srv.URL)
	require.NoError(t, err, "a failed rediscovery keeps the old verifier")
	assert.Same(t, second, third)

	_, err = iv.get(ds.srv.URL)
	require.NoError(t, err)
	assert.Equal(t, int64(3), ds.fetches.Load(), "the failed rediscovery is not retried within the interval")
}
