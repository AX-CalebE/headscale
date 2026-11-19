package apiv2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestTokenCanAssignTags(t *testing.T) {
	for _, s := range []scope.Scope{scope.AuthKeys, scope.DevicesCore, scope.OAuthKeys, scope.FederatedKeys, scope.All} {
		assert.True(t, tokenCanAssignTags([]scope.Scope{s}), s)
	}

	for _, s := range []scope.Scope{scope.FederatedKeysRead, scope.OAuthKeysRead, scope.Users, scope.AllRead} {
		assert.False(t, tokenCanAssignTags([]scope.Scope{s}), s)
	}
}

// TestNarrowTagsRejectsMalformed asserts the token endpoint validates tag
// format at the trust boundary. An "all"-scope client may assign any tag, but a
// malformed tag (missing the "tag:" prefix) must still be rejected rather than
// flowing unvalidated into auth-key creation.
func TestNarrowTagsRejectsMalformed(t *testing.T) {
	all := &types.OAuthClient{Scopes: []string{"all"}}

	_, bad, ok := narrowTags(all, []string{"not-a-tag"})
	assert.False(t, ok, "malformed tag must be rejected even with all scope")
	assert.Equal(t, "not-a-tag", bad)

	got, _, ok := narrowTags(all, []string{"tag:anything"})
	assert.True(t, ok, "all scope may assign any well-formed tag")
	assert.Equal(t, []string{"tag:anything"}, got)

	// A scoped client may only assign its own well-formed tags.
	scoped := &types.OAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}}

	_, bad, ok = narrowTags(scoped, []string{"tag:other"})
	assert.False(t, ok)
	assert.Equal(t, "tag:other", bad)
}
