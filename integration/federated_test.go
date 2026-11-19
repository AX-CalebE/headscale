package integration

import (
	"slices"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const tagCI = "tag:ci"

// TestFederatedIdentityTailscaleUp registers a real client with
// `tailscale up --client-id --id-token`, exchanging an ID token from an https
// OIDC issuer that a federated identity trusts, and checks that a token whose
// subject the identity does not trust registers nothing.
func TestFederatedIdentityTailscaleUp(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{
		Users:     []string{},
		OIDCHTTPS: true,
		OIDCUsers: []mockoidc.MockUser{
			{Subject: "repo:acme/app:ref:refs/heads/main"},
			{Subject: "repo:other/app:ref:refs/heads/main"},
		},
	})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{},
		hsic.WithTestName("federated"),
		hsic.WithCACert(scenario.mockOIDC.CACert()),
		hsic.WithACLPolicy(&policyv2.Policy{
			TagOwners: policyv2.TagOwners{policyv2.Tag(tagCI): policyv2.Owners{}},
		}),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	clientID, err := headscale.CreateFederatedIdentity(t.Context(),
		scenario.mockOIDC.Issuer(), "repo:acme/*", scenario.mockOIDC.ClientID(), []string{tagCI})
	require.NoError(t, err)

	trusted, err := scenario.mockOIDC.IDToken(t.Context())
	require.NoError(t, err)

	untrusted, err := scenario.mockOIDC.IDToken(t.Context())
	require.NoError(t, err)

	up := func(client TailscaleClient, idToken string) error {
		_, _, err := client.Execute([]string{
			"tailscale", "up",
			"--login-server=" + headscale.GetEndpoint(),
			"--hostname=" + client.Hostname(),
			"--advertise-tags=" + tagCI,
			"--client-id=" + clientID,
			"--id-token=" + idToken,
		}, dockertestutil.ExecuteCommandTimeout(time.Minute))

		return err
	}

	registered := func(hostname string) []string {
		nodes, err := headscale.ListNodes()
		require.NoError(t, err)

		for _, n := range nodes {
			if n.Name == hostname {
				return n.Tags
			}
		}

		return nil
	}

	newClient := func() TailscaleClient {
		client, err := scenario.CreateTailscaleNode("head",
			tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]))
		require.NoError(t, err)

		return client
	}

	refused := newClient()
	err = up(refused, untrusted)
	require.ErrorContains(t, err, "token exchange failed with status 403")
	assert.Nil(t, registered(refused.Hostname()), "an untrusted subject registers no node")

	joined := newClient()
	require.NoError(t, up(joined, trusted))

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := joined.Status()
		assert.NoError(c, err)
		assert.Equal(c, "Running", status.BackendState)
		assert.True(c, status.Self.Tags != nil && slices.Contains(status.Self.Tags.AsSlice(), tagCI))
	}, integrationutil.ScaledTimeout(30*time.Second), integrationutil.FastPoll, "waiting for the federated client to run")

	assert.Equal(t, []string{tagCI}, registered(joined.Hostname()))
}
