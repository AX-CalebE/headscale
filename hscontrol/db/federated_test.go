package db

import (
	"errors"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// requireFederationMigration checks a migrated pre-federation fixture (node 1 holds credential 1; node 2 and credential 6 deleted).
func requireFederationMigration(t *testing.T, hsdb *HSDatabase, preAuthKey, accessToken, clientID string) {
	t.Helper()

	nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
		return ListNodes(rx)
	})
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.NotNil(t, nodes[0].AuthKey)
	assert.Equal(t, uint64(1), nodes[0].AuthKey.ID, "the node keeps its key")

	pak, err := hsdb.GetPreAuthKey(preAuthKey)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), pak.ID)

	_, err = hsdb.AuthenticateAccessToken(accessToken)
	require.NoError(t, err, "an access token survives the migration")

	newKey, err := hsdb.CreatePreAuthKey(nil, false, false, nil, []string{"tag:x"})
	require.NoError(t, err)
	assert.Greater(t, newKey.ID, uint64(6), "credential ids deleted before the migration are not reused")

	requireCredentialConstraints(t, hsdb.DB)

	user := hsdb.CreateUserForTest("federation-migration")
	node := hsdb.CreateRegisteredNodeForTest(user)
	assert.Greater(t, uint64(node.ID), uint64(2), "node ids deleted before the migration are not reused")

	_, err = hsdb.CreateFederatedIdentity(validFederatedIdentity(), "headscale.example.com")
	require.NoError(t, err)

	clash := types.Credential{Kind: types.CredentialFederatedIdentity, Identifier: clientID, Issuer: "https://issuer.example.com", Subject: "x"}
	requireConstraintFailed(t, hsdb.DB.Omit("Hash").Create(&clash).Error)
}

func forEachBackend(t *testing.T, test func(*testing.T, *HSDatabase)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) { test(t, dbForTest(t)) })
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

func validFederatedIdentity() types.FederatedIdentity {
	return types.FederatedIdentity{
		Issuer:  "https://token.actions.githubusercontent.com",
		Subject: "repo:acme/*",
		Scopes:  []string{"auth_keys"},
		Tags:    []string{"tag:ci"},
	}
}

func TestFederatedIdentityValidation(t *testing.T) {
	forEachBackend(t, testFederatedIdentityValidation)
}

func testFederatedIdentityValidation(t *testing.T, db *HSDatabase) {
	t.Helper()

	tests := []struct {
		name   string
		mutate func(*types.FederatedIdentity)
		want   string
	}{
		{"http_issuer", func(fi *types.FederatedIdentity) { fi.Issuer = "http://issuer.example.com" }, string(errIssuerInvalid)},
		{"no_host", func(fi *types.FederatedIdentity) { fi.Issuer = "https://" }, string(errIssuerInvalid)},
		{"no_subject", func(fi *types.FederatedIdentity) { fi.Subject = "" }, string(errSubjectMissing)},
		{
			"aud_rule", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = map[string]string{"aud": "x"} },
			`cannot use "aud" as a custom claim rule since this claim is already checked against the "audience" field`,
		},
		{
			"quoted_aud_rule", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = map[string]string{`"aud"`: "x"} },
			`cannot use "aud" as a custom claim rule since this claim is already checked against the "audience" field`,
		},
		{"empty_rule", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = map[string]string{"": "x"} }, `custom claim rule "" is not a valid claim path`},
		{"empty_segment", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = map[string]string{"a..b": "x"} }, `custom claim rule "a..b" is not a valid claim path`},
		{"unbalanced_quote", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = map[string]string{`"repo.owner`: "x"} }, `custom claim rule "\"repo.owner" is not a valid claim path`},
		{"unknown_scope", func(fi *types.FederatedIdentity) { fi.Scopes = []string{"nope"} }, "nope"},
		{"bad_tag", func(fi *types.FederatedIdentity) { fi.Tags = []string{"ci"} }, "ci"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fi := validFederatedIdentity()
			tt.mutate(&fi)

			_, err := db.CreateFederatedIdentity(fi, "headscale.example.com")
			require.ErrorContains(t, err, tt.want)
		})
	}
}

func TestUpdateFederatedIdentityTokens(t *testing.T) {
	forEachBackend(t, testUpdateFederatedIdentityTokens)
}

func testUpdateFederatedIdentityTokens(t *testing.T, db *HSDatabase) {
	t.Helper()

	base := func() types.FederatedIdentity {
		fi := validFederatedIdentity()
		fi.CustomClaimRules = map[string]string{"repository_owner": "acme"}
		fi.Scopes = []string{"auth_keys", "devices:core:read"}
		fi.Tags = []string{"tag:ci", "tag:deploy"}

		return fi
	}

	tests := []struct {
		name       string
		mutate     func(*types.FederatedIdentity)
		keepsToken bool
	}{
		{"description", func(fi *types.FederatedIdentity) { fi.Description = "other" }, true},
		{"omitted_audience", func(fi *types.FederatedIdentity) { fi.Audience = "" }, true},
		{"claim_rule_removed", func(fi *types.FederatedIdentity) { fi.CustomClaimRules = nil }, true},
		{"scope_added", func(fi *types.FederatedIdentity) { fi.Scopes = append(fi.Scopes, "users") }, true},
		{"scope_widened", func(fi *types.FederatedIdentity) { fi.Scopes = []string{"auth_keys", "devices:core"} }, true},
		{"tag_added", func(fi *types.FederatedIdentity) { fi.Tags = append(fi.Tags, "tag:extra") }, true},
		{"issuer", func(fi *types.FederatedIdentity) { fi.Issuer = "https://issuer.example.com" }, false},
		{"subject", func(fi *types.FederatedIdentity) { fi.Subject = "repo:acme/app:*" }, false},
		{"audience", func(fi *types.FederatedIdentity) { fi.Audience = "elsewhere" }, false},
		{"claim_rule_added", func(fi *types.FederatedIdentity) { fi.CustomClaimRules["environment"] = "prod" }, false},
		{"claim_rule_changed", func(fi *types.FederatedIdentity) { fi.CustomClaimRules["repository_owner"] = "other" }, false},
		{"scope_removed", func(fi *types.FederatedIdentity) { fi.Scopes = []string{"auth_keys"} }, false},
		{"tag_removed", func(fi *types.FederatedIdentity) { fi.Tags = []string{"tag:ci"} }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			created, err := db.CreateFederatedIdentity(base(), "headscale.example.com")
			require.NoError(t, err)

			expiry := time.Now().Add(time.Hour)
			tokenStr, _, err := db.ExchangeFederatedToken(created.ClientID, admitAll, &expiry)
			require.NoError(t, err)

			update := base()
			update.Audience = created.Audience
			tt.mutate(&update)
			_, err = db.UpdateFederatedIdentity(created.ClientID, update)
			require.NoError(t, err)

			_, err = db.AuthenticateAccessToken(tokenStr)
			if tt.keepsToken {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestExchangeFederatedTokenConcurrentUpdate(t *testing.T) {
	forEachBackend(t, testExchangeFederatedTokenConcurrentUpdate)
}

func testExchangeFederatedTokenConcurrentUpdate(t *testing.T, db *HSDatabase) {
	t.Helper()

	created, err := db.CreateFederatedIdentity(validFederatedIdentity(), "headscale.example.com")
	require.NoError(t, err)

	type exchange struct {
		token string
		err   error
	}

	admitting := make(chan struct{})
	release := make(chan struct{})
	exchanged := make(chan exchange, 1)

	go func() {
		expiry := time.Now().Add(time.Hour)
		tokenStr, _, err := db.ExchangeFederatedToken(created.ClientID, func(*types.FederatedIdentity) error {
			close(admitting)
			<-release

			return nil
		}, &expiry)

		exchanged <- exchange{tokenStr, err}
	}()

	<-admitting

	updated := make(chan error, 1)

	go func() {
		update := validFederatedIdentity()
		update.Subject = "repo:acme/app:*"
		_, err := db.UpdateFederatedIdentity(created.ClientID, update)

		updated <- err
	}()

	// An update that does not wait for the exchange finishes here, before the token is saved.
	select {
	case err := <-updated:
		updated <- err
	case <-time.After(500 * time.Millisecond):
	}

	close(release)

	ex := <-exchanged
	require.NoError(t, ex.err)
	require.NoError(t, <-updated)

	_, err = db.AuthenticateAccessToken(ex.token)
	require.Error(t, err, "a token admitted under the old subject does not survive the update")
}

func TestExchangeFederatedTokenConcurrentDelete(t *testing.T) {
	forEachBackend(t, testExchangeFederatedTokenConcurrentDelete)
}

func testExchangeFederatedTokenConcurrentDelete(t *testing.T, db *HSDatabase) {
	t.Helper()

	created, err := db.CreateFederatedIdentity(validFederatedIdentity(), "headscale.example.com")
	require.NoError(t, err)

	admitting := make(chan struct{})
	release := make(chan struct{})
	exchanged := make(chan error, 1)

	go func() {
		expiry := time.Now().Add(time.Hour)
		_, _, err := db.ExchangeFederatedToken(created.ClientID, func(*types.FederatedIdentity) error {
			close(admitting)
			<-release

			return nil
		}, &expiry)

		exchanged <- err
	}()

	<-admitting

	deleted := make(chan error, 1)

	go func() {
		deleted <- db.DeleteFederatedIdentity(created.ClientID)
	}()

	// A delete that does not wait for the exchange finishes here, before the token is saved.
	select {
	case err := <-deleted:
		deleted <- err
	case <-time.After(500 * time.Millisecond):
	}

	close(release)

	require.NoError(t, <-exchanged)
	require.NoError(t, <-deleted)

	var tokens int64
	require.NoError(t, db.DB.Model(&types.Credential{}).
		Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, created.ClientID).Count(&tokens).Error)
	assert.Zero(t, tokens, "a token exchanged during the delete is deleted with the identity")
}

var errSubjectChanged = errors.New("subject changed")

func admitAll(*types.FederatedIdentity) error { return nil }

func TestExchangeFederatedToken(t *testing.T) {
	forEachBackend(t, testExchangeFederatedToken)
}

func testExchangeFederatedToken(t *testing.T, db *HSDatabase) {
	t.Helper()

	created, err := db.CreateFederatedIdentity(validFederatedIdentity(), "headscale.example.com")
	require.NoError(t, err)

	update := validFederatedIdentity()
	update.Subject = "repo:acme/app:*"
	update.Scopes = []string{"auth_keys", "devices:core"}
	_, err = db.UpdateFederatedIdentity(created.ClientID, update)
	require.NoError(t, err)

	expiry := time.Now().Add(time.Hour)
	checkedAgainstRead := func(fi *types.FederatedIdentity) error {
		if fi.Subject != created.Subject {
			return errSubjectChanged
		}

		return nil
	}

	_, _, err = db.ExchangeFederatedToken(created.ClientID, checkedAgainstRead, &expiry)
	require.ErrorIs(t, err, ErrFederatedExchangeRefused, "admission sees the identity as stored at mint time")

	var tokens int64
	require.NoError(t, db.DB.Model(&types.Credential{}).
		Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, created.ClientID).Count(&tokens).Error)
	assert.Zero(t, tokens)

	_, token, err := db.ExchangeFederatedToken(created.ClientID, admitAll, &expiry)
	require.NoError(t, err)
	assert.Equal(t, []string{"auth_keys", "devices:core"}, token.Scopes, "the token carries the stored scopes")

	_, _, err = db.ExchangeFederatedToken("000000000000", admitAll, &expiry)
	require.ErrorIs(t, err, ErrFederatedIdentityNotFound)

	_, _, err = db.MintAccessToken(created.ClientID, created.Scopes, created.Tags, &expiry)
	require.ErrorIs(t, err, ErrOAuthClientNotFound, "a federated identity mints only through the exchange")
}

func TestFederatedIdentityLifecycle(t *testing.T) {
	forEachBackend(t, testFederatedIdentityLifecycle)
}

func testFederatedIdentityLifecycle(t *testing.T, db *HSDatabase) {
	t.Helper()

	user := db.CreateUserForTest("creator")

	fi := validFederatedIdentity()
	fi.UserID = &user.ID

	created, err := db.CreateFederatedIdentity(fi, "headscale.example.com")
	require.NoError(t, err)
	require.Len(t, created.ClientID, keyIdentifierLength)
	assert.Equal(t, "headscale.example.com/"+created.ClientID, created.Audience)
	assert.Equal(t, map[string]string{}, created.CustomClaimRules)
	assert.Nil(t, created.UpdatedAt)

	expiry := time.Now().Add(time.Hour)
	tokenStr, _, err := db.ExchangeFederatedToken(created.ClientID, admitAll, &expiry)
	require.NoError(t, err)

	token, err := db.AuthenticateAccessToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, created.ClientID, token.ClientID)

	relabel := validFederatedIdentity()
	relabel.Description = "relabelled"
	_, err = db.UpdateFederatedIdentity(created.ClientID, relabel)
	require.NoError(t, err)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.NoError(t, err, "an update leaving every trust setting unchanged keeps tokens")

	update := validFederatedIdentity()
	update.Subject = "repo:acme/app:*"
	updated, err := db.UpdateFederatedIdentity(created.ClientID, update)
	require.NoError(t, err)
	assert.Equal(t, "repo:acme/app:*", updated.Subject)
	assert.Equal(t, created.Audience, updated.Audience)
	assert.NotNil(t, updated.UpdatedAt)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.Error(t, err, "an update deletes tokens minted under the old settings")

	tokenStr, _, err = db.ExchangeFederatedToken(created.ClientID, admitAll, &expiry)
	require.NoError(t, err)

	require.NoError(t, db.DestroyUser(types.UserID(user.ID)))
	orphan, err := db.GetFederatedIdentity(created.ClientID)
	require.NoError(t, err)
	assert.Nil(t, orphan.UserID, "deleting the creator clears it")

	require.NoError(t, db.DeleteFederatedIdentity(created.ClientID))
	require.ErrorIs(t, db.DeleteFederatedIdentity(created.ClientID), ErrFederatedIdentityNotFound)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.Error(t, err, "a token dies with its identity")

	_, _, err = db.ExchangeFederatedToken(created.ClientID, admitAll, &expiry)
	require.ErrorIs(t, err, ErrFederatedIdentityNotFound)
}
