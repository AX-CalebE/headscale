package servertest_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "tailscale.com/feature/identityfederation"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// testIssuer is a TLS OIDC issuer that signs whatever claims a test asks for.
type testIssuer struct {
	srv         *httptest.Server
	key         *rsa.PrivateKey
	jwksFetches atomic.Int64
}

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	iss := &testIssuer{key: key}
	mux := http.NewServeMux()
	iss.srv = httptest.NewTLSServer(mux)
	t.Cleanup(iss.srv.Close)

	b64 := base64.RawURLEncoding.EncodeToString

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.srv.URL,
			"jwks_uri":                              iss.srv.URL + "/jwks",
			"authorization_endpoint":                iss.srv.URL + "/authorize",
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		iss.jwksFetches.Add(1)

		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test",
			"alg": "RS256",
			"use": "sig",
			"n":   b64(key.N.Bytes()),
			"e":   b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})

	return iss
}

// token signs claims over the issuer's defaults (iss, sub, aud, iat, exp).
func (iss *testIssuer) token(t *testing.T, aud string, claims map[string]any) string {
	t.Helper()

	return signJWT(t, iss.key, iss.claims(aud, claims))
}

func (iss *testIssuer) claims(aud string, extra map[string]any) map[string]any {
	now := time.Now()
	claims := map[string]any{
		"iss": iss.srv.URL,
		"sub": "repo:acme/app:ref:refs/heads/main",
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}

	for k, v := range extra {
		if v == nil {
			delete(claims, k)

			continue
		}

		claims[k] = v
	}

	return claims
}

func signJWT(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()

	enc := func(v any) string {
		b, err := json.Marshal(v)
		require.NoError(t, err)

		return base64.RawURLEncoding.EncodeToString(b)
	}

	signing := enc(map[string]string{"alg": "RS256", "kid": "test", "typ": "JWT"}) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	require.NoError(t, err)

	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type apiResponse struct {
	status      int
	contentType string
	body        []byte
}

func (r apiResponse) json(t *testing.T) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(r.body, &m), "body: %s", r.body)

	return m
}

func apiDo(t *testing.T, method, target, bearer, contentType string, body []byte) apiResponse {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, target, bytes.NewReader(body))
	require.NoError(t, err)

	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return apiResponse{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: b}
}

func apiJSON(t *testing.T, method, target, bearer string, body any) apiResponse {
	t.Helper()

	var b []byte

	if body != nil {
		var err error

		b, err = json.Marshal(body)
		require.NoError(t, err)
	}

	return apiDo(t, method, target, bearer, "application/json", b)
}

func exchange(t *testing.T, baseURL string, form url.Values) apiResponse {
	t.Helper()

	return apiDo(t, http.MethodPost, baseURL+"/api/v2/oauth/token-exchange", "",
		"application/x-www-form-urlencoded", []byte(form.Encode()))
}

func newFederationServer(t *testing.T) (*servertest.TestServer, *testIssuer, string) {
	t.Helper()

	iss := newTestIssuer(t)
	srv := servertest.NewServer(t,
		servertest.WithRealListener(),
		servertest.WithFederationHTTPClient(iss.srv.Client()),
	)
	owner := srv.CreateUser(t, "apiv2-oauth")
	setScopeMatrixPolicy(t, srv)

	return srv, iss, srv.CreateAPIKey(t, owner)
}

func createFederated(t *testing.T, srv *servertest.TestServer, apiKey string, body map[string]any) map[string]any {
	t.Helper()

	req := map[string]any{
		"keyType":     "federated",
		"description": "ci",
		"scopes":      []string{"auth_keys"},
		"tags":        []string{"tag:ci"},
	}
	maps.Copy(req, body)

	resp := apiJSON(t, http.MethodPost, srv.URL+"/api/v2/tailnet/-/keys", apiKey, req)
	require.Equal(t, http.StatusOK, resp.status, "body: %s", resp.body)

	return resp.json(t)
}

func keyIDs(t *testing.T, resp apiResponse) []string {
	t.Helper()

	var list struct {
		Keys []struct {
			ID string `json:"id"`
		} `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(resp.body, &list))

	ids := make([]string, 0, len(list.Keys))
	for _, k := range list.Keys {
		ids = append(ids, k.ID)
	}

	return ids
}

// TestAPIv2FederatedIdentityKeys pins federated identity keys operations to Tailscale's captured answers.
func TestAPIv2FederatedIdentityKeys(t *testing.T) {
	srv, iss, apiKey := newFederationServer(t)
	keys := srv.URL + "/api/v2/tailnet/-/keys"
	host := strings.TrimPrefix(srv.URL, "http://")

	created := createFederated(t, srv, apiKey, map[string]any{
		"issuer":  iss.srv.URL,
		"subject": "repo:acme/*",
	})
	id, _ := created["id"].(string)
	require.Regexp(t, `^[0-9a-f]{12}$`, id, "the OAuth client id format")

	fields := slices.Sorted(func(yield func(string) bool) {
		for k := range created {
			if !yield(k) {
				return
			}
		}
	})
	assert.Equal(t, []string{
		"audience", "created", "customClaimRules", "description", "id", "issuer",
		"keyType", "scopes", "subject", "tags", "userId",
	}, fields)
	assert.Equal(t, "federated", created["keyType"])
	assert.Equal(t, host+"/"+id, created["audience"])
	assert.Equal(t, map[string]any{}, created["customClaimRules"])

	got := apiJSON(t, http.MethodGet, keys+"/"+id, apiKey, nil)
	require.Equal(t, http.StatusOK, got.status)
	assert.Equal(t, created, got.json(t))

	assert.NotContains(t, keyIDs(t, apiJSON(t, http.MethodGet, keys, apiKey, nil)), id,
		"listed only with all=true")
	assert.Contains(t, keyIDs(t, apiJSON(t, http.MethodGet, keys+"?all=true", apiKey, nil)), id)

	put := apiJSON(t, http.MethodPut, keys+"/"+id, apiKey, map[string]any{
		"keyType":          "federated",
		"description":      "ci updated",
		"scopes":           []string{"auth_keys"},
		"tags":             []string{"tag:ci"},
		"issuer":           iss.srv.URL,
		"subject":          "repo:acme/app:*",
		"customClaimRules": map[string]string{"repository_owner": "acme"},
	})
	require.Equal(t, http.StatusOK, put.status, "body: %s", put.body)

	updated := put.json(t)
	assert.Equal(t, "ci updated", updated["description"])
	assert.Equal(t, host+"/"+id, updated["audience"], "an omitted audience is kept")
	assert.Equal(t, map[string]any{"repository_owner": "acme"}, updated["customClaimRules"])
	assert.Contains(t, updated, "updated")

	del := apiJSON(t, http.MethodDelete, keys+"/"+id, apiKey, nil)
	require.Equal(t, http.StatusOK, del.status)
	assert.Equal(t, http.StatusNotFound, apiJSON(t, http.MethodGet, keys+"/"+id, apiKey, nil).status)

	refused := []struct {
		name string
		body map[string]any
		want string
	}{
		{
			name: "not_a_url",
			body: map[string]any{"issuer": "not-a-url", "subject": "x"},
			want: "federated identities must have an issuer defined that is a valid and publicly reachable https:// URL",
		},
		{
			name: "http_issuer",
			body: map[string]any{"issuer": "http://issuer.example.com", "subject": "x"},
			want: "federated identities must have an issuer defined that is a valid and publicly reachable https:// URL",
		},
		{
			name: "iss_rule",
			body: map[string]any{"issuer": iss.srv.URL, "subject": "x", "customClaimRules": map[string]string{"iss": "https://*"}},
			want: `cannot use "iss" as a custom claim rule since this claim is already checked against the "issuer" field`,
		},
		{
			name: "sub_rule",
			body: map[string]any{"issuer": iss.srv.URL, "subject": "x", "customClaimRules": map[string]string{"sub": "*"}},
			want: `cannot use "sub" as a custom claim rule since this claim is already checked against the "subject" field`,
		},
	}
	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			req := map[string]any{"keyType": "federated", "scopes": []string{"auth_keys"}, "tags": []string{"tag:ci"}}
			maps.Copy(req, tt.body)

			resp := apiJSON(t, http.MethodPost, keys, apiKey, req)
			require.Equal(t, http.StatusBadRequest, resp.status, "body: %s", resp.body)
			assert.Equal(t, tt.want, resp.json(t)["message"])
		})
	}
}

// TestAPIv2FederatedTokenExchange pins token-exchange answers and claim matching to Tailscale's.
func TestAPIv2FederatedTokenExchange(t *testing.T) {
	srv, iss, apiKey := newFederationServer(t)

	newIdentity := func(t *testing.T, subject string, rules map[string]string) string {
		t.Helper()

		body := map[string]any{"issuer": iss.srv.URL, "subject": subject, "audience": "headscale"}
		if rules != nil {
			body["customClaimRules"] = rules
		}

		id, _ := createFederated(t, srv, apiKey, body)["id"].(string)

		return id
	}

	exact := newIdentity(t, "repo:acme/app:ref:refs/heads/main", nil)

	t.Run("ok", func(t *testing.T) {
		resp := exchange(t, srv.URL, url.Values{"client_id": {exact}, "jwt": {iss.token(t, "headscale", nil)}})
		require.Equal(t, http.StatusOK, resp.status, "body: %s", resp.body)

		body := resp.json(t)
		assert.Equal(t, "Bearer", body["token_type"])
		assert.InDelta(t, 3600, body["expires_in"], 0)
		assert.Equal(t, "auth_keys", body["scope"])
		assert.Equal(t, "tag:ci", body["tags"])

		token, _ := body["access_token"].(string)
		require.True(t, strings.HasPrefix(token, types.AccessTokenPrefix))

		own := apiJSON(t, http.MethodGet, srv.URL+"/api/v2/tailnet/-/keys/"+exact, token, nil)
		assert.Equal(t, http.StatusNotFound, own.status, "an auth_keys token cannot read its identity")
	})

	matching := []struct {
		name    string
		subject string
		rules   map[string]string
		aud     string
		claims  map[string]any
		ok      bool
	}{
		{name: "audience_mismatch", subject: "*", aud: "elsewhere"},
		{name: "subject_mismatch", subject: "repo:other/*"},
		{name: "subject_wildcard", subject: "repo:acme/*:ref:refs/heads/*", ok: true},
		{name: "subject_star", subject: "*", ok: true},
		{name: "claim_match", subject: "*", rules: map[string]string{"repository_owner": "acme"}, claims: map[string]any{"repository_owner": "acme"}, ok: true},
		{name: "claim_mismatch", subject: "*", rules: map[string]string{"repository_owner": "acme"}, claims: map[string]any{"repository_owner": "evil"}},
		{name: "claim_wildcard", subject: "*", rules: map[string]string{"azp": "*.apps.example.com"}, claims: map[string]any{"azp": "123.apps.example.com"}, ok: true},
		{name: "bool_claim", subject: "*", rules: map[string]string{"email_verified": "true"}, claims: map[string]any{"email_verified": true}, ok: true},
		{name: "absent_claim_star", subject: "*", rules: map[string]string{"repo.name": "*"}},
		{name: "nested_claim", subject: "*", rules: map[string]string{"repo.name": "app"}, claims: map[string]any{"repo": map[string]any{"name": "app"}}, ok: true},
		{name: "quoted_dot_claim", subject: "*", rules: map[string]string{`"repo.name"`: "app"}, claims: map[string]any{"repo.name": "app"}, ok: true},
		{name: "quoted_dot_not_nested", subject: "*", rules: map[string]string{`"repo.name"`: "app"}, claims: map[string]any{"repo": map[string]any{"name": "app"}}},
		{name: "expired", subject: "*", claims: map[string]any{"exp": time.Now().Add(-time.Minute).Unix()}},
	}
	for _, tt := range matching {
		t.Run(tt.name, func(t *testing.T) {
			id := newIdentity(t, tt.subject, tt.rules)

			aud := tt.aud
			if aud == "" {
				aud = "headscale"
			}

			resp := exchange(t, srv.URL, url.Values{"client_id": {id}, "jwt": {iss.token(t, aud, tt.claims)}})
			if tt.ok {
				assert.Equal(t, http.StatusOK, resp.status, "body: %s", resp.body)

				return
			}

			assert.Equal(t, http.StatusForbidden, resp.status, "body: %s", resp.body)
			assert.Equal(t, map[string]any{"message": "Unauthorized"}, resp.json(t))
		})
	}

	t.Run("wrong_signing_key", func(t *testing.T) {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		fetches := iss.jwksFetches.Load()

		for range 5 {
			resp := exchange(t, srv.URL, url.Values{"client_id": {exact}, "jwt": {signJWT(t, other, iss.claims("headscale", nil))}})
			assert.Equal(t, http.StatusForbidden, resp.status)
		}

		assert.Equal(t, fetches, iss.jwksFetches.Load(), "forged tokens do not refetch the issuer's keys")
	})

	t.Run("issuer_unreachable", func(t *testing.T) {
		body := map[string]any{"issuer": "https://127.0.0.1:1", "subject": "*", "audience": "headscale"}
		id, _ := createFederated(t, srv, apiKey, body)["id"].(string)

		resp := exchange(t, srv.URL, url.Values{"client_id": {id}, "jwt": {iss.token(t, "headscale", nil)}})
		assert.Equal(t, http.StatusBadGateway, resp.status)
		assert.Equal(t, map[string]any{"message": "could not reach the token issuer"}, resp.json(t))
	})

	t.Run("garbage_jwt", func(t *testing.T) {
		resp := exchange(t, srv.URL, url.Values{"client_id": {exact}, "jwt": {"not.a.jwt"}})
		assert.Equal(t, http.StatusForbidden, resp.status)
		assert.Equal(t, map[string]any{"message": "Unauthorized"}, resp.json(t))
	})

	t.Run("missing_jwt", func(t *testing.T) {
		resp := exchange(t, srv.URL, url.Values{"client_id": {exact}})
		assert.Equal(t, http.StatusBadRequest, resp.status)
		assert.Equal(t, map[string]any{"message": "request must include a jwt"}, resp.json(t))
	})

	invalid := []struct {
		name string
		resp func(t *testing.T) apiResponse
	}{
		{"unknown_client", func(t *testing.T) apiResponse {
			t.Helper()

			return exchange(t, srv.URL, url.Values{"client_id": {"nonexistentclient"}, "jwt": {iss.token(t, "headscale", nil)}})
		}},
		{"missing_client", func(t *testing.T) apiResponse {
			t.Helper()

			return exchange(t, srv.URL, url.Values{"jwt": {iss.token(t, "headscale", nil)}})
		}},
		{"json_body", func(t *testing.T) apiResponse {
			t.Helper()

			return apiJSON(t, http.MethodPost, srv.URL+"/api/v2/oauth/token-exchange", "",
				map[string]string{"client_id": exact, "jwt": iss.token(t, "headscale", nil)})
		}},
	}
	for _, tt := range invalid {
		t.Run(tt.name, func(t *testing.T) {
			resp := tt.resp(t)
			assert.Equal(t, http.StatusBadRequest, resp.status)
			assert.True(t, strings.HasPrefix(resp.contentType, "text/plain"), resp.contentType)
			assert.Equal(t, "invalid request\n", string(resp.body))
		})
	}

	t.Run("token_dies_with_identity", func(t *testing.T) {
		id := newIdentity(t, "*", nil)

		resp := exchange(t, srv.URL, url.Values{"client_id": {id}, "jwt": {iss.token(t, "headscale", nil)}})
		require.Equal(t, http.StatusOK, resp.status)

		token, _ := resp.json(t)["access_token"].(string)
		require.Equal(t, http.StatusOK, apiJSON(t, http.MethodDelete, srv.URL+"/api/v2/tailnet/-/keys/"+id, apiKey, nil).status)

		after := apiJSON(t, http.MethodGet, srv.URL+"/api/v2/tailnet/-/keys", token, nil)
		assert.Equal(t, http.StatusUnauthorized, after.status)
	})
}

// TestAPIv2FederatedTailscaleClient registers through the stock client's --client-id/--id-token path, via tsnet.
func TestAPIv2FederatedTailscaleClient(t *testing.T) {
	srv, iss, apiKey := newFederationServer(t)

	id, _ := createFederated(t, srv, apiKey, map[string]any{
		"issuer":  iss.srv.URL,
		"subject": "repo:acme/*",
	})["id"].(string)
	aud, _ := apiJSON(t, http.MethodGet, srv.URL+"/api/v2/tailnet/-/keys/"+id, apiKey, nil).json(t)["audience"].(string)

	tests := []struct {
		name          string
		clientID      string
		idToken       string
		tags          []string
		wantErr       string
		wantEphemeral bool
	}{
		{
			// The client defaults ephemeral to true when unset.
			name:          "defaults_ephemeral",
			clientID:      id,
			idToken:       iss.token(t, aud, nil),
			tags:          []string{"tag:ci"},
			wantEphemeral: true,
		},
		{
			name:     "not_ephemeral",
			clientID: id + "?ephemeral=false",
			idToken:  iss.token(t, aud, nil),
			tags:     []string{"tag:ci"},
		},
		{
			name:     "subject_mismatch",
			clientID: id,
			idToken:  iss.token(t, aud, map[string]any{"sub": "repo:other/app"}),
			tags:     []string{"tag:ci"},
			wantErr:  "status 403",
		},
		{
			name:     "unknown_client",
			clientID: "nonexistentclient",
			idToken:  iss.token(t, aud, nil),
			tags:     []string{"tag:ci"},
			wantErr:  "status 400",
		},
		{
			name:     "tag_not_granted",
			clientID: id,
			idToken:  iss.token(t, aud, nil),
			tags:     []string{"tag:other"},
			wantErr:  "tag:other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostname := "wif-" + strings.ReplaceAll(tt.name, "_", "-")

			ts := &tsnet.Server{
				Dir:           t.TempDir(),
				Hostname:      hostname,
				ControlURL:    srv.URL,
				AdvertiseTags: tt.tags,
				ClientID:      tt.clientID,
				IDToken:       tt.idToken,
				Logf:          logger.Discard,
			}
			t.Cleanup(func() { ts.Close() })

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()

			_, err := ts.Up(ctx)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				for _, n := range srv.State().ListNodes().All() {
					require.NotEqual(t, hostname, n.Hostname(), "no node may register")
				}

				return
			}

			require.NoError(t, err)

			var node types.NodeView

			for _, n := range srv.State().ListNodes().All() {
				if n.Hostname() == hostname {
					node = n
				}
			}

			require.True(t, node.Valid(), "node %q not registered", hostname)
			assert.True(t, node.IsTagged())
			assert.Equal(t, []string{"tag:ci"}, node.Tags().AsSlice())
			assert.Equal(t, tt.wantEphemeral, node.IsEphemeral())
		})
	}
}
