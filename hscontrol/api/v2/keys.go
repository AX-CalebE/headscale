package apiv2

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
)

func init() {
	registrations = append(registrations, registerKeys)
}

// defaultExpiry is the auth-key lifetime when the request omits expirySeconds,
// and the longest it may ask for: 90 days, as Tailscale.
const defaultExpiry = 90 * 24 * time.Hour

const (
	// keyTypeAuth is a machine auth key (Headscale pre-auth key); the default.
	keyTypeAuth = "auth"
	// keyTypeClient is an OAuth client (client-credentials). Multiplexed onto the
	// keys resource exactly as Tailscale does.
	keyTypeClient = "client"
	// keyTypeFederated is a federated identity (workload identity federation).
	keyTypeFederated = "federated"
)

// KeyCapabilities maps a resource to the actions a key permits. Headscale
// populates only devices.create (auth keys); the named types (vs Tailscale's
// anonymous nesting) give Huma stable schema names.
type KeyCapabilities struct {
	_ struct{} `additionalProperties:"true"`

	Devices KeyDeviceCapabilities `json:"devices"`
}

type KeyDeviceCapabilities struct {
	_ struct{} `additionalProperties:"true"`

	Create KeyDeviceCreateCapabilities `json:"create"`
}

type KeyDeviceCreateCapabilities struct {
	_ struct{} `additionalProperties:"true"`

	Reusable      bool `json:"reusable"`
	Ephemeral     bool `json:"ephemeral"`
	Preauthorized bool `json:"preauthorized"`
	// Tags is not nullable:"false" nor required: the Tailscale clients send
	// "tags":null for an untagged key and SaaS takes it left out. The response
	// always emits [] via emptyIfNil.
	Tags []string `json:"tags" required:"false"`
}

// CreateKeyRequest is the POST body. It is multiplexed by keyType: "auth"
// (default) creates a machine auth key from Capabilities; "client" creates an
// OAuth client from the top-level Scopes and Tags. expirySeconds is plain
// seconds (unlike the response, see Key).
type CreateKeyRequest struct {
	// Unknown properties are ignored, as Tailscale's API does.
	_ struct{} `additionalProperties:"true"`

	KeyType string `doc:"Key kind: \"auth\" (default), \"client\" (OAuth client) or \"federated\" (federated identity)." json:"keyType,omitempty"`
	// Capabilities is optional: an auth key carries device-create capabilities,
	// but an OAuth client (keyType:"client") has none and the Tailscale clients
	// omit the field entirely, so it must not be required.
	Capabilities  *KeyCapabilities `json:"capabilities,omitempty"`
	ExpirySeconds int64            `doc:"Lifetime in seconds, 0 to 90 days; 0 or omitted means 90 days. Auth keys only." json:"expirySeconds,omitempty"`
	Description   string           `json:"description,omitempty"                                                         maxLength:"50"`
	// Scopes and Tags are top-level and apply only to keyType "client" (an OAuth
	// client). Auth-key tags live under Capabilities.Devices.Create.Tags.
	Scopes []string `doc:"OAuth scopes granted to the client or federated identity. keyType=client or federated." json:"scopes,omitempty"`
	Tags   []string `doc:"Tags the client or federated identity may assign. keyType=client or federated."         json:"tags,omitempty"`

	Issuer           string            `doc:"https:// issuer of the OIDC tokens to exchange. keyType=federated only."                 json:"issuer,omitempty"`
	Subject          string            `doc:"Pattern the sub claim must match; * matches any characters. keyType=federated only."     json:"subject,omitempty"`
	Audience         string            `doc:"Value the aud claim must contain; generated when omitted. keyType=federated only."       json:"audience,omitempty"`
	CustomClaimRules map[string]string `doc:"Further claims (dotted paths) and the patterns they must match. keyType=federated only." json:"customClaimRules,omitempty"`
}

// Key is the Tailscale key response, shared by auth keys, OAuth clients and
// federated identities. expirySeconds is emitted in seconds to match the
// Tailscale spec; the secret key is present only at creation.
type Key struct {
	ID               string            `json:"id"`
	KeyType          string            `json:"keyType"`
	Key              string            `json:"key,omitempty"`
	Description      string            `json:"description,omitempty"`
	ExpirySeconds    int64             `json:"expirySeconds,omitempty"`
	Created          time.Time         `json:"created"`
	Updated          *time.Time        `json:"updated,omitempty"`
	Expires          *time.Time        `json:"expires,omitempty"`
	Revoked          *time.Time        `json:"revoked,omitempty"`
	Invalid          *bool             `json:"invalid,omitempty"`
	Capabilities     *KeyCapabilities  `json:"capabilities,omitempty"`
	Scopes           []string          `json:"scopes,omitempty"`
	Tags             []string          `json:"tags,omitempty"`
	Audience         string            `json:"audience,omitempty"`
	Issuer           string            `json:"issuer,omitempty"`
	Subject          string            `json:"subject,omitempty"`
	CustomClaimRules map[string]string `json:"customClaimRules,omitzero"`
	UserID           string            `json:"userId,omitempty"`
}

type (
	createKeyInput struct {
		Tailnet string `doc:"Tailnet; must be \"-\" (the single Headscale tailnet)." path:"tailnet"`
		Body    CreateKeyRequest
	}

	listKeysInput struct {
		Tailnet string `path:"tailnet"`
		All     bool   `doc:"Without it, federated identities are left out, and a token sees only the auth keys tokens made." query:"all"`
	}

	keyByIDInput struct {
		Tailnet string `path:"tailnet"`
		KeyID   string `path:"keyId"`
	}

	setTrustKeyInput struct {
		Tailnet string `path:"tailnet"`
		KeyID   string `path:"keyId"`
		Body    CreateKeyRequest
	}

	keyOutput struct {
		Body Key
	}

	listKeysOutput struct {
		Body struct {
			Keys []Key `json:"keys" nullable:"false"`
		}
	}

	deleteKeyOutput struct {
		Body struct{}
	}
)

// The keys resource is multiplexed by keyType (auth key vs OAuth client), so the
// scope an operation requires depends on the request rather than being fixed.
// requireScope (which the middleware enforces statically) is therefore omitted
// here; each handler authorizes via requireKeyScope once the kind is known.
func registerKeys(api huma.API, b Backend) {
	keysTags := []string{"Keys", "Tailscale compat"}

	huma.Register(api, huma.Operation{
		OperationID:  "createKey",
		Method:       http.MethodPost,
		Path:         "/api/v2/tailnet/{tailnet}/keys",
		Summary:      "Create an auth key, OAuth client or federated identity",
		Description:  "Requires the `auth_keys` scope for an auth key, `oauth_keys` for an OAuth client, or `federated_keys` for a federated identity (an admin API key is all-access).",
		Tags:         keysTags,
		Security:     security,
		Middlewares:  huma.Middlewares{requireCreateKeyScope(api)},
		MaxBodyBytes: maxBodyBytes,
		Errors: []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *createKeyInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		switch in.Body.KeyType {
		case keyTypeClient:
			return createOAuthClient(ctx, b, in.Body)
		case keyTypeFederated:
			return createFederatedIdentity(ctx, b, in.Body)
		case "", keyTypeAuth:
			return createAuthKey(ctx, b, in.Body)
		default:
			return nil, huma.Error400BadRequest(
				"invalid key type, " + strconv.Quote(in.Body.KeyType) + " is not supported",
			)
		}
	})

	huma.Register(api, huma.Operation{
		OperationID: "listKeys",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys",
		Summary:     "List auth keys, OAuth clients and federated identities",
		Description: "A token sees the kinds it can read: `auth_keys:read` for auth keys, `oauth_keys:read` for OAuth clients, `federated_keys:read` for federated identities (an admin API key sees all). Federated identities are listed only with `all=true`.",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *listKeysInput) (*listKeysOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		scopes, isOAuth := principalScopes(ctx)

		out := &listKeysOutput{}
		out.Body.Keys = []Key{}

		// A token sees the key kinds it has read scope for; an admin key sees all.
		if !isOAuth || scope.Grants(scope.Parse(scopes), scope.AuthKeysRead) {
			keys, err := b.State.ListPreAuthKeys()
			if err != nil {
				return nil, huma.Error500InternalServerError("listing auth keys", err)
			}

			now := time.Now()

			// As Tailscale lists them: never an invalid key, and to a token
			// without all=true only the keys tokens made.
			for i := range keys {
				if !keyVisibleInList(&keys[i], now, isOAuth, in.All) {
					continue
				}

				out.Body.Keys = append(out.Body.Keys, keyFromStored(&keys[i]))
			}
		}

		if !isOAuth || scope.Grants(scope.Parse(scopes), scope.OAuthKeysRead) {
			clients, err := b.State.ListOAuthClients()
			if err != nil {
				return nil, huma.Error500InternalServerError("listing oauth clients", err)
			}

			for i := range clients {
				out.Body.Keys = append(out.Body.Keys, oauthClientToKey(&clients[i], ""))
			}
		}

		return out, appendFederatedIdentityKeys(&out.Body.Keys, b, scopes, isOAuth, in.All)
	})

	huma.Register(api, huma.Operation{
		OperationID: "getKey",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:     "Get an auth key, OAuth client or federated identity",
		Description: "Requires `auth_keys:read` for an auth key, `oauth_keys:read` for an OAuth client, or `federated_keys:read` for a federated identity (an admin API key is all-access).",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *keyByIDInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		out, err := getTrustCredentialKey(ctx, b, in.KeyID)
		if err != nil {
			return nil, err
		}

		if out != nil {
			return out, nil
		}

		err = requireKeyScope(ctx, scope.AuthKeysRead)
		if err != nil {
			return nil, err
		}

		key, err := findKeyByID(b, in.KeyID)
		if err != nil {
			return nil, err
		}

		return &keyOutput{Body: keyFromStored(key)}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "deleteKey",
		Method:        http.MethodDelete,
		Path:          "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:       "Delete an auth key, OAuth client or federated identity",
		Description:   "Requires the `auth_keys` scope for an auth key, `oauth_keys` for an OAuth client, or `federated_keys` for a federated identity (an admin API key is all-access).",
		Tags:          keysTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, func(ctx context.Context, in *keyByIDInput) (*deleteKeyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		deleted, err := deleteTrustCredentialKey(ctx, b, in.KeyID)
		if err != nil {
			return nil, err
		}

		if deleted {
			return &deleteKeyOutput{}, nil
		}

		err = requireKeyScope(ctx, scope.AuthKeys)
		if err != nil {
			return nil, err
		}

		id, err := parseID(in.KeyID, "auth key")
		if err != nil {
			return nil, err
		}

		// Tailscale's DELETE revokes the key but keeps it retrievable (invalid)
		// rather than destroying it; the collector reaps it after the retention
		// window.
		err = b.State.RevokePreAuthKey(id)
		if err != nil {
			return nil, mapError("revoking auth key", err)
		}

		return &deleteKeyOutput{}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:  "setKey",
		Method:       http.MethodPut,
		Path:         "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:      "Set a federated identity",
		Description:  "Replaces a federated identity's configuration. Only keyType `federated` is supported.",
		Tags:         keysTags,
		Security:     security,
		MaxBodyBytes: maxBodyBytes,
		Errors: []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, scope.FederatedKeys), func(ctx context.Context, in *setTrustKeyInput) (*keyOutput, error) {
		return setFederatedIdentity(ctx, b, in)
	})
}

func keyVisibleInList(key *types.PreAuthKey, now time.Time, isOAuth, all bool) bool {
	if key.ValidAt(now) != nil {
		return false
	}

	return !isOAuth || all || key.CreatedByToken
}

// requireKeyScope authorizes a keys operation for an OAuth access token. An admin
// API key carries no OAuth scopes and is all-access, so it always passes.
func requireKeyScope(ctx context.Context, need scope.Scope) error {
	scopes, isOAuth := principalScopes(ctx)
	if !isOAuth {
		return nil
	}

	if !scope.Grants(scope.Parse(scopes), need) {
		return huma.Error403Forbidden("token is missing the required scope " + string(need))
	}

	return nil
}

// requireCreateKeyScope refuses, before huma reads the body, a token that may
// create neither kind of key; the handler then checks the kind it got.
func requireCreateKeyScope(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if requireKeyScope(ctx.Context(), scope.AuthKeys) != nil &&
			requireKeyScope(ctx.Context(), scope.OAuthKeys) != nil &&
			requireKeyScope(ctx.Context(), scope.FederatedKeys) != nil {
			_ = huma.WriteErr(api, ctx, http.StatusForbidden,
				"token is missing the required scope auth_keys, oauth_keys or federated_keys")

			return
		}

		next(ctx)
	}
}

// createAuthKey creates a machine auth key (pre-auth key). Ownership: tags -> a
// tagged key; no tags -> owned by the API key's user. An OAuth access token must
// mint tagged keys, and each tag must be within the token's grant.
func createAuthKey(ctx context.Context, b Backend, body CreateKeyRequest) (*keyOutput, error) {
	err := requireKeyScope(ctx, scope.AuthKeys)
	if err != nil {
		return nil, err
	}

	switch {
	case body.ExpirySeconds < 0:
		return nil, huma.Error400BadRequest("expirySeconds must be greater than or equal to 0")
	case body.ExpirySeconds > int64(defaultExpiry/time.Second):
		return nil, huma.Error400BadRequest("expirySeconds must be less than or equal to " +
			strconv.FormatInt(int64(defaultExpiry/time.Second), 10))
	}

	var create KeyDeviceCreateCapabilities
	if body.Capabilities != nil {
		create = body.Capabilities.Devices.Create
	}

	tokenTags, isOAuth := principalTags(ctx)

	var userID *types.UserID

	switch {
	case len(create.Tags) > 0:
		// A key minted by an OAuth token may only carry tags within the token's
		// grant (held directly, or owned by a held tag) and defined in policy,
		// matching SetNodeTags. An admin key keeps the historical behaviour of
		// validating only tag syntax (db.validateACLTags), and records its
		// user as the key's creator.
		if !isOAuth {
			if uid, ok := ownerUser(ctx); ok {
				userID = &uid
			}
		}

		if isOAuth {
			for _, tag := range create.Tags {
				if !b.State.TagExists(tag) {
					return nil, huma.Error400BadRequest("tag " + tag + " is not defined in policy")
				}
			}

			if refused := unownedTags(b, create.Tags, tokenTags); len(refused) > 0 {
				return nil, tagsRefused("", refused)
			}
		}

	case isOAuth:
		// OAuth-minted keys are tailnet/tag-owned; an untagged (user-owned) key
		// cannot be created from a token.
		return nil, huma.Error403Forbidden("an OAuth client must create tagged auth keys")

	default:
		uid, ok := ownerUser(ctx)
		if !ok {
			return nil, huma.Error400BadRequest(
				"an auth key without tags must be created with a user-owned API key",
			)
		}

		userID = &uid
	}

	expiration := time.Now().Add(expiryDuration(body.ExpirySeconds))

	createKey := b.State.CreatePreAuthKey
	if isOAuth {
		createKey = b.State.CreateTokenPreAuthKey
	}

	pak, err := createKey(
		userID,
		create.Reusable,
		create.Ephemeral,
		&expiration,
		create.Tags,
	)
	if err != nil {
		return nil, mapError("creating auth key", err)
	}

	if body.Description != "" {
		err := b.State.SetPreAuthKeyDescription(pak.ID, body.Description)
		if err != nil {
			return nil, huma.Error500InternalServerError("setting auth key description", err)
		}
	}

	return &keyOutput{Body: keyFromNew(pak, body)}, nil
}

// createOAuthClient creates an OAuth client (keyType:"client"). The client secret
// is returned once, here.
func createOAuthClient(ctx context.Context, b Backend, body CreateKeyRequest) (*keyOutput, error) {
	err := requireKeyScope(ctx, scope.OAuthKeys)
	if err != nil {
		return nil, err
	}

	err = checkTrustCredentialGrant(ctx, b, oauthClientNoun, body.Scopes, body.Tags)
	if err != nil {
		return nil, err
	}

	var creator *uint

	if uid, ok := ownerUser(ctx); ok {
		u := uint(uid)
		creator = &u
	}

	secret, client, err := b.State.CreateOAuthClient(body.Scopes, body.Tags, body.Description, creator)
	if err != nil {
		return nil, mapError("creating oauth client", err)
	}

	return &keyOutput{Body: oauthClientToKey(client, secret)}, nil
}

// appendFederatedIdentityKeys appends federated identities to a list with all=true for a caller holding federated_keys:read.
func appendFederatedIdentityKeys(keys *[]Key, b Backend, scopes []string, isOAuth, all bool) error {
	if !all || (isOAuth && !scope.Grants(scope.Parse(scopes), scope.FederatedKeysRead)) {
		return nil
	}

	fis, err := b.State.ListFederatedIdentities()
	if err != nil {
		return huma.Error500InternalServerError("listing federated identities", err)
	}

	for i := range fis {
		*keys = append(*keys, federatedIdentityToKey(&fis[i]))
	}

	return nil
}

// trustCredential returns the OAuth client or federated identity id names; both are nil if it names neither.
func trustCredential(b Backend, id string) (*types.OAuthClient, *types.FederatedIdentity, error) {
	client, fi, err := b.State.GetTokenIssuer(id)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil, nil
	}

	if err != nil {
		return nil, nil, huma.Error500InternalServerError("looking up key", err)
	}

	return client, fi, nil
}

// getTrustCredentialKey returns the trust credential id names, or nil if none or the caller lacks read scope for its kind.
func getTrustCredentialKey(ctx context.Context, b Backend, id string) (*keyOutput, error) {
	client, fi, err := trustCredential(b, id)
	if err != nil {
		return nil, err
	}

	switch {
	case client != nil && requireKeyScope(ctx, scope.OAuthKeysRead) == nil:
		return &keyOutput{Body: oauthClientToKey(client, "")}, nil
	case fi != nil && requireKeyScope(ctx, scope.FederatedKeysRead) == nil:
		return &keyOutput{Body: federatedIdentityToKey(fi)}, nil
	}

	return nil, nil //nolint:nilnil // Not a trust credential the caller may read; the caller tries an auth key.
}

// deleteTrustCredentialKey deletes the trust credential id names, reporting false if none or the caller lacks write scope.
func deleteTrustCredentialKey(ctx context.Context, b Backend, id string) (bool, error) {
	client, fi, err := trustCredential(b, id)
	if err != nil {
		return false, err
	}

	switch {
	case client != nil && requireKeyScope(ctx, scope.OAuthKeys) == nil:
		err = b.State.RevokeOAuthClient(id)
		if err != nil {
			return false, mapError("deleting oauth client", err)
		}

		return true, nil
	case fi != nil && requireKeyScope(ctx, scope.FederatedKeys) == nil:
		err = b.State.DeleteFederatedIdentity(id)
		if err != nil {
			return false, mapError("deleting federated identity", err)
		}

		b.verifiers.forget(fi.Issuer)

		return true, nil
	}

	return false, nil
}

func setFederatedIdentity(ctx context.Context, b Backend, in *setTrustKeyInput) (*keyOutput, error) {
	err := requireDefaultTailnet(in.Tailnet)
	if err != nil {
		return nil, err
	}

	if in.Body.KeyType != keyTypeFederated {
		return nil, huma.Error400BadRequest(
			"invalid key type, " + strconv.Quote(in.Body.KeyType) + " is not supported",
		)
	}

	err = checkTrustCredentialGrant(ctx, b, federatedIdentityNoun, in.Body.Scopes, in.Body.Tags)
	if err != nil {
		return nil, err
	}

	old, err := b.State.GetFederatedIdentity(in.KeyID)
	if err != nil {
		return nil, mapError("looking up federated identity", err)
	}

	fi, err := b.State.UpdateFederatedIdentity(in.KeyID, federatedIdentityFromRequest(in.Body))
	if err != nil {
		return nil, mapError("updating federated identity", err)
	}

	b.verifiers.forget(old.Issuer)
	b.verifiers.forget(fi.Issuer)

	return &keyOutput{Body: federatedIdentityToKey(fi)}, nil
}

// createFederatedIdentity creates a federated identity (keyType:"federated").
func createFederatedIdentity(ctx context.Context, b Backend, body CreateKeyRequest) (*keyOutput, error) {
	err := requireKeyScope(ctx, scope.FederatedKeys)
	if err != nil {
		return nil, err
	}

	err = checkTrustCredentialGrant(ctx, b, federatedIdentityNoun, body.Scopes, body.Tags)
	if err != nil {
		return nil, err
	}

	fi := federatedIdentityFromRequest(body)

	if uid, ok := ownerUser(ctx); ok {
		u := uint(uid)
		fi.UserID = &u
	}

	created, err := b.State.CreateFederatedIdentity(fi, federatedAudiencePrefix(b))
	if err != nil {
		return nil, mapError("creating federated identity", err)
	}

	return &keyOutput{Body: federatedIdentityToKey(created)}, nil
}

// federatedAudiencePrefix is server_url's host, which prefixes a generated audience as api.tailscale.com does Tailscale's.
func federatedAudiencePrefix(b Backend) string {
	if b.Cfg == nil {
		return ""
	}

	u, err := url.Parse(b.Cfg.ServerURL)
	if err != nil {
		return ""
	}

	return u.Host
}

func federatedIdentityFromRequest(body CreateKeyRequest) types.FederatedIdentity {
	return types.FederatedIdentity{
		Issuer:           body.Issuer,
		Subject:          body.Subject,
		Audience:         body.Audience,
		CustomClaimRules: body.CustomClaimRules,
		Description:      body.Description,
		Scopes:           body.Scopes,
		Tags:             body.Tags,
	}
}

// The resource names checkTrustCredentialGrant's messages use.
const (
	oauthClientNoun       = "an OAuth client"
	federatedIdentityNoun = "a federated identity"
)

// checkTrustCredentialGrant validates a trust credential's scopes and tags, refusing authority beyond a creating token's.
func checkTrustCredentialGrant(ctx context.Context, b Backend, noun string, scopes, tags []string) error {
	if len(scopes) == 0 {
		return huma.Error400BadRequest(noun + " must declare at least one scope")
	}

	// Tailscale: tags are mandatory when the scopes include devices:core or
	// auth_keys, because such a client mints tagged, tailnet-owned credentials.
	if scope.RequiresTags(scope.Parse(scopes)) && len(tags) == 0 {
		return huma.Error400BadRequest(
			"tags are required when scopes include devices:core or auth_keys",
		)
	}

	// A client created by an OAuth token may not be granted authority the token
	// lacks: its scopes must each be within the token's grant, and its tags within
	// the token's tags and defined in policy (matching SetNodeTags). Otherwise an
	// oauth_keys token could mint an all-access client and escalate. An admin API
	// key (not an OAuth token) is unrestricted and keeps the historical tag
	// behaviour (syntax-only validation).
	tokenScopes, isOAuth := principalScopes(ctx)
	if !isOAuth {
		return nil
	}

	for _, s := range scopes {
		if !scope.Grants(scope.Parse(tokenScopes), scope.Scope(s)) {
			return huma.Error403Forbidden(
				noun + " may not be granted scope " + s + " beyond the creating token",
			)
		}
	}

	tokenTags, _ := principalTags(ctx)

	// An untagged "all" client may mint tokens for any tag (narrowTags), so a
	// tag-limited token would escape its tags one client away.
	if len(tokenTags) > 0 && canAssignAnyTag(tags, scopes) {
		return huma.Error403Forbidden(
			noun + " may not be granted scope all without tags by a tagged token",
		)
	}

	for _, tag := range tags {
		if !b.State.TagExists(tag) {
			return huma.Error400BadRequest("tag " + tag + " is not defined in policy")
		}
	}

	if refused := unownedTags(b, tags, tokenTags); len(refused) > 0 {
		return tagsRefused("", refused)
	}

	return nil
}

// findKeyByID looks up a stored pre-auth key by its (stringified) id with a
// direct by-id query; an unknown id surfaces as gorm.ErrRecordNotFound, which
// mapError turns into a 404.
func findKeyByID(b Backend, rawID string) (*types.PreAuthKey, error) {
	id, err := parseID(rawID, "auth key")
	if err != nil {
		return nil, err
	}

	pak, err := b.State.GetPreAuthKeyByID(id)
	if err != nil {
		return nil, mapError("looking up auth key", err)
	}

	return pak, nil
}

// keyFromNew builds the create response from the freshly created key. The
// plaintext secret is returned only here. preauthorized is reported true to
// match keyFromStored: Headscale always authorizes pre-auth-key nodes, so the
// create and read paths must agree or the Terraform provider sees a diff.
func keyFromNew(pak *types.PreAuthKeyNew, req CreateKeyRequest) Key {
	var create KeyDeviceCreateCapabilities
	if req.Capabilities != nil {
		create = req.Capabilities.Devices.Create
	}

	key := Key{
		ID:          pak.StringID(),
		KeyType:     keyTypeAuth,
		Key:         pak.Key,
		Description: req.Description,
		Created:     timeOrZero(pak.CreatedAt),
		Invalid:     new(false),
		Capabilities: capabilities(
			create.Reusable,
			create.Ephemeral,
			true,
			pak.Tags,
		),
		Tags: pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	// A user-owned key reports its owner, a tagged key its creator.
	if pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

// keyFromStored builds the get/list response from a stored key. The secret is
// never returned here. preauthorized is reported true: Headscale has no separate
// device-approval step, so every pre-auth key authorizes its nodes. Reporting it
// stably keeps the Terraform provider from seeing a forced-replacement diff.
func keyFromStored(pak *types.PreAuthKey) Key {
	key := Key{
		ID:           pak.StringID(),
		KeyType:      keyTypeAuth,
		Description:  pak.Description,
		Created:      timeOrZero(pak.CreatedAt),
		Invalid:      new(pak.Validate() != nil),
		Capabilities: capabilities(pak.Reusable, pak.Ephemeral, true, pak.Tags),
		Tags:         pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	if pak.Revoked != nil {
		key.Revoked = pak.Revoked
	}

	if pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

// oauthClientToKey builds the keys response for an OAuth client. secret is the
// plaintext client secret, set only on the create response and empty on get/list
// (the secret is never re-exposed).
func oauthClientToKey(client *types.OAuthClient, secret string) Key {
	key := Key{
		ID:           client.ClientID,
		KeyType:      keyTypeClient,
		Key:          secret,
		Description:  client.Description,
		Created:      timeOrZero(client.CreatedAt),
		Invalid:      new(client.Revoked != nil),
		Revoked:      client.Revoked,
		Capabilities: &KeyCapabilities{},
		Scopes:       emptyIfNil(client.Scopes),
		Tags:         emptyIfNil(client.Tags),
	}

	if client.UserID != nil {
		key.UserID = strconv.FormatUint(uint64(*client.UserID), util.Base10)
	}

	return key
}

// federatedIdentityToKey builds the keys response for a federated identity.
func federatedIdentityToKey(fi *types.FederatedIdentity) Key {
	key := Key{
		ID:               fi.ClientID,
		KeyType:          keyTypeFederated,
		Description:      fi.Description,
		Created:          timeOrZero(fi.CreatedAt),
		Updated:          fi.UpdatedAt,
		Scopes:           emptyIfNil(fi.Scopes),
		Tags:             emptyIfNil(fi.Tags),
		Audience:         fi.Audience,
		Issuer:           fi.Issuer,
		Subject:          fi.Subject,
		CustomClaimRules: fi.CustomClaimRules,
	}

	if key.CustomClaimRules == nil {
		key.CustomClaimRules = map[string]string{}
	}

	if fi.UserID != nil {
		key.UserID = strconv.FormatUint(uint64(*fi.UserID), util.Base10)
	}

	return key
}

func capabilities(
	reusable, ephemeral, preauthorized bool,
	tags []string,
) *KeyCapabilities {
	return &KeyCapabilities{
		Devices: KeyDeviceCapabilities{Create: KeyDeviceCreateCapabilities{
			Reusable:      reusable,
			Ephemeral:     ephemeral,
			Preauthorized: preauthorized,
			Tags:          emptyIfNil(tags),
		}},
	}
}

func expiryDuration(seconds int64) time.Duration {
	if seconds <= 0 {
		return defaultExpiry
	}

	return time.Duration(seconds) * time.Second
}
