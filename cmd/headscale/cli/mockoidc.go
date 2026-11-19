package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	errMockOidcClientIDNotDefined     = errors.New("MOCKOIDC_CLIENT_ID not defined")
	errMockOidcClientSecretNotDefined = errors.New("MOCKOIDC_CLIENT_SECRET not defined")
	errMockOidcPortNotDefined         = errors.New("MOCKOIDC_PORT not defined")
	errMockOidcUsersNotDefined        = errors.New("MOCKOIDC_USERS not defined")
)

const refreshTTL = 60 * time.Minute

var accessTTL = 2 * time.Minute

func init() {
	rootCmd.AddCommand(mockOidcCmd)
}

var mockOidcCmd = &cobra.Command{
	Use:   "mockoidc",
	Short: "Runs a mock OIDC server for testing",
	Long:  "This internal command runs a OpenID Connect for testing purposes",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := mockOIDC()
		if err != nil {
			return fmt.Errorf("running mock OIDC server: %w", err)
		}

		return nil
	},
}

func mockOIDC() error {
	clientID := os.Getenv("MOCKOIDC_CLIENT_ID")
	if clientID == "" {
		return errMockOidcClientIDNotDefined
	}

	clientSecret := os.Getenv("MOCKOIDC_CLIENT_SECRET")
	if clientSecret == "" {
		return errMockOidcClientSecretNotDefined
	}

	addrStr := os.Getenv("MOCKOIDC_ADDR")
	if addrStr == "" {
		return errMockOidcPortNotDefined
	}

	portStr := os.Getenv("MOCKOIDC_PORT")
	if portStr == "" {
		return errMockOidcPortNotDefined
	}

	accessTTLOverride := os.Getenv("MOCKOIDC_ACCESS_TTL")
	if accessTTLOverride != "" {
		newTTL, err := time.ParseDuration(accessTTLOverride)
		if err != nil {
			return err
		}

		accessTTL = newTTL
	}

	userStr := os.Getenv("MOCKOIDC_USERS")
	if userStr == "" {
		return errMockOidcUsersNotDefined
	}

	var users []mockoidc.MockUser

	err := json.Unmarshal([]byte(userStr), &users)
	if err != nil {
		return fmt.Errorf("unmarshalling users: %w", err)
	}

	log.Info().Interface(zf.Users, users).Msg("loading users from JSON")

	log.Info().Msgf("access token TTL: %s", accessTTL)

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	mock, err := getMockOIDC(clientID, clientSecret, users)
	if err != nil {
		return err
	}

	listener, err := new(net.ListenConfig).Listen(context.Background(), "tcp", fmt.Sprintf("%s:%d", addrStr, port))
	if err != nil {
		return err
	}

	var tlsConfig *tls.Config

	if certPath := os.Getenv("MOCKOIDC_TLS_CERT"); certPath != "" {
		addr, _ := listener.Addr().(*net.TCPAddr)

		tlsConfig, err = selfSignedTLS(addr.IP, certPath)
		if err != nil {
			return err
		}

		listener = tls.NewListener(listener, tlsConfig)
	}

	err = mock.Start(listener, tlsConfig)
	if err != nil {
		return err
	}

	log.Info().Msgf("mock OIDC server listening on %s", listener.Addr().String())
	log.Info().Msgf("issuer: %s", mock.Issuer())

	c := make(chan struct{})
	<-c

	return nil
}

// selfSignedTLS issues a self-signed certificate for ip, writes it as PEM to certPath for clients to trust, and returns a server config using it.
func selfSignedTLS(ip net.IP, certPath string) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: ip.String()},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{ip},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644) //nolint:gosec // A public certificate.
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func getMockOIDC(clientID string, clientSecret string, users []mockoidc.MockUser) (*mockoidc.MockOIDC, error) {
	keypair, err := mockoidc.NewKeypair(nil)
	if err != nil {
		return nil, err
	}

	userQueue := mockoidc.UserQueue{}

	for _, user := range users {
		userQueue.Push(&user)
	}

	mock := mockoidc.MockOIDC{
		ClientID:                      clientID,
		ClientSecret:                  clientSecret,
		AccessTTL:                     accessTTL,
		RefreshTTL:                    refreshTTL,
		CodeChallengeMethodsSupported: []string{"plain", "S256"},
		Keypair:                       keypair,
		SessionStore:                  mockoidc.NewSessionStore(),
		UserQueue:                     &userQueue,
		ErrorQueue:                    &mockoidc.ErrorQueue{},
	}

	_ = mock.AddMiddleware(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Info().Msgf("request: %+v", r)
			h.ServeHTTP(w, r)

			if r.Response != nil {
				log.Info().Msgf("response: %+v", r.Response)
			}
		})
	})

	return &mock, nil
}
