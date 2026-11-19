package db

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"tailscale.com/util/rands"
	"tailscale.com/util/set"
)

var (
	ErrFederatedIdentityNotFound = fmt.Errorf("federated identity not found: %w", gorm.ErrRecordNotFound)
	ErrFederatedIdentityInvalid  = errors.New("federated identity invalid")
	ErrFederatedExchangeRefused  = errors.New("federated token exchange refused")
)

// federatedIdentityError is a refusal whose message is Tailscale's whole answer.
type federatedIdentityError string

func (e federatedIdentityError) Error() string { return string(e) }

func (federatedIdentityError) Is(target error) bool { return target == ErrFederatedIdentityInvalid }

const (
	errIssuerInvalid  federatedIdentityError = "federated identities must have an issuer defined that is a valid and publicly reachable https:// URL"
	errSubjectMissing federatedIdentityError = "federated identities must have a subject defined"
)

// federatedClaimFields maps claims a dedicated field checks, which custom claim rules may not, to that field.
var federatedClaimFields = map[string]string{
	"iss": "issuer",
	"sub": "subject",
	"aud": "audience",
}

// credentialsColumnsBeforeFederation are the credentials columns a database had before federated identities.
//
//nolint:gosec // column list, not a credential
const credentialsColumnsBeforeFederation = `id, kind, identifier, hash, user_id, description, scopes, tags, reusable, ephemeral, used, last_seen, client_id, created_at, expiration, revoked, created_by_token`

const nodesColumns = `id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6, last_control_address, hostname, given_name, user_id, register_method, tags, auth_key_id, ephemeral, last_seen, expiry, approved_routes, auto_approved_routes, created_at, updated_at, deleted_at`

// nodesDDLReferencingCredentialsNew is schema.sql's nodes table, named and keyed for the SQLite rebuild.
const nodesDDLReferencingCredentialsNew = `CREATE TABLE nodes_new(
  id integer PRIMARY KEY AUTOINCREMENT,
  machine_key text,
  node_key text,
  disco_key text,

  endpoints text,
  host_info text,
  ipv4 text,
  ipv6 text,
  last_control_address text,
  hostname text,
  given_name varchar(63),
  user_id integer,
  register_method text,
  tags text,
  auth_key_id integer,
  ephemeral numeric DEFAULT false,
  last_seen datetime,
  expiry datetime,
  approved_routes text,
  auto_approved_routes text,

  created_at datetime,
  updated_at datetime,
  deleted_at datetime,

  CONSTRAINT fk_nodes_user FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_nodes_auth_key FOREIGN KEY(auth_key_id) REFERENCES credentials_new(id)
)`

// migrateCredentialsFederatedIdentity adds the federated_identity kind and its columns to credentials.
func migrateCredentialsFederatedIdentity(tx *gorm.DB) error {
	if tx.Migrator().HasColumn(&types.Credential{}, "issuer") {
		return nil
	}

	return tx.Transaction(func(tx *gorm.DB) error {
		if tx.Name() == sqlite.DriverName {
			return rebuildCredentialsSQLite(tx)
		}

		return alterCredentialsPostgres(tx)
	})
}

// rebuildCredentialsSQLite rebuilds credentials, and nodes with it, since SQLite cannot alter a CHECK and foreign keys stay on.
func rebuildCredentialsSQLite(tx *gorm.DB) error {
	sequences := map[string]int64{}

	for _, table := range []string{"credentials", "nodes"} {
		seq, err := sqliteSequence(tx, table)
		if err != nil {
			return err
		}

		sequences[table] = seq
	}

	stmts := slices.Concat([]string{
		strings.Replace(credentialsDDLSQLite, "CREATE TABLE credentials(", "CREATE TABLE credentials_new(", 1),
		`INSERT INTO credentials_new (` + credentialsColumnsBeforeFederation + `) SELECT ` + credentialsColumnsBeforeFederation + ` FROM credentials`,
		nodesDDLReferencingCredentialsNew,
		`INSERT INTO nodes_new (` + nodesColumns + `) SELECT ` + nodesColumns + ` FROM nodes`,
		`DROP TABLE nodes`,
		`DROP TABLE credentials`,
		`ALTER TABLE credentials_new RENAME TO credentials`,
		`ALTER TABLE nodes_new RENAME TO nodes`,
		`CREATE INDEX idx_nodes_auth_key_id ON nodes(auth_key_id)`,
	}, credentialIndexes)

	for _, stmt := range stmts {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("rebuilding credentials and nodes: %w", err)
		}
	}

	for table, seq := range sequences {
		err := raiseSQLiteSequence(tx, table, seq)
		if err != nil {
			return err
		}
	}

	return nil
}

// sqliteSequence returns the AUTOINCREMENT counter of table, 0 if unset.
func sqliteSequence(tx *gorm.DB, table string) (int64, error) {
	var seq int64

	err := tx.Raw(`SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = ?`, table).
		Scan(&seq).Error
	if err != nil {
		return 0, fmt.Errorf("reading %s sequence: %w", table, err)
	}

	return seq, nil
}

// raiseSQLiteSequence sets the AUTOINCREMENT counter of table to at least seq.
func raiseSQLiteSequence(tx *gorm.DB, table string, seq int64) error {
	res := tx.Exec(`UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?`, seq, table)
	if res.Error == nil && res.RowsAffected == 0 && seq > 0 {
		// No row yet: nothing has been inserted into table.
		res = tx.Exec(`INSERT INTO sqlite_sequence(name, seq) VALUES(?, ?)`, table, seq)
	}

	if res.Error != nil {
		return fmt.Errorf("restoring %s sequence: %w", table, res.Error)
	}

	return nil
}

func alterCredentialsPostgres(tx *gorm.DB) error {
	stmts := []string{
		`ALTER TABLE credentials
  ADD COLUMN issuer text,
  ADD COLUMN subject text,
  ADD COLUMN audience text,
  ADD COLUMN custom_claim_rules text,
  ADD COLUMN updated_at timestamptz`,
		`ALTER TABLE credentials DROP CONSTRAINT credentials_kind_check`,
		`ALTER TABLE credentials ADD CONSTRAINT credentials_kind_check CHECK(kind IN ('api','authkey','oauth_client','oauth_token','federated_identity'))`,
		`ALTER TABLE credentials DROP CONSTRAINT chk_credentials_hash`,
		`ALTER TABLE credentials ADD CONSTRAINT chk_credentials_hash CHECK(hash IS NOT NULL OR revoked IS NOT NULL OR kind = 'federated_identity')`,
		credentialsTokenIssuerIndex,
	}

	for _, stmt := range stmts {
		err := tx.Exec(stmt).Error
		if err != nil {
			return fmt.Errorf("altering credentials: %w", err)
		}
	}

	return nil
}

// validateFederatedIdentity normalises fi's scopes and tags and refuses one that could never match a token.
func validateFederatedIdentity(fi *types.FederatedIdentity) error {
	tags, err := validateACLTags(fi.Tags)
	if err != nil {
		return err
	}

	err = validateScopes(fi.Scopes)
	if err != nil {
		return err
	}

	scopes := set.SetOf(fi.Scopes).Slice()
	slices.Sort(scopes)

	fi.Tags = tags
	fi.Scopes = scopes

	issuer, err := url.Parse(fi.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" {
		return errIssuerInvalid
	}

	if fi.Subject == "" {
		return errSubjectMissing
	}

	for _, rule := range slices.Sorted(maps.Keys(fi.CustomClaimRules)) {
		path := types.SplitClaimPath(rule)
		if slices.Contains(path, "") || strings.Count(rule, `"`)%2 != 0 {
			return federatedIdentityError("custom claim rule " + strconv.Quote(rule) + " is not a valid claim path")
		}

		if field, ok := federatedClaimFields[path[0]]; ok && len(path) == 1 {
			return federatedIdentityError("cannot use " + strconv.Quote(path[0]) +
				" as a custom claim rule since this claim is already checked against the " +
				strconv.Quote(field) + " field")
		}
	}

	if fi.CustomClaimRules == nil {
		fi.CustomClaimRules = map[string]string{}
	}

	return nil
}

// CreateFederatedIdentity stores fi under a new client id; an empty audience becomes audiencePrefix/<client id>.
func (hsdb *HSDatabase) CreateFederatedIdentity(
	fi types.FederatedIdentity,
	audiencePrefix string,
) (*types.FederatedIdentity, error) {
	err := validateFederatedIdentity(&fi)
	if err != nil {
		return nil, err
	}

	clientID := rands.HexString(keyIdentifierLength)

	if fi.Audience == "" {
		fi.Audience = audiencePrefix + "/" + clientID
	}

	now := time.Now().UTC()
	cred := types.Credential{
		Kind:             types.CredentialFederatedIdentity,
		Identifier:       clientID,
		Issuer:           fi.Issuer,
		Subject:          fi.Subject,
		Audience:         fi.Audience,
		CustomClaimRules: fi.CustomClaimRules,
		Description:      fi.Description,
		Scopes:           fi.Scopes,
		Tags:             fi.Tags,
		UserID:           fi.UserID,
		CreatedAt:        &now,
	}

	err = hsdb.Write(func(tx *gorm.DB) error {
		return tx.Omit("Hash").Create(&cred).Error
	})
	if err != nil {
		return nil, fmt.Errorf("saving federated identity: %w", err)
	}

	return credentialToFederatedIdentity(&cred), nil
}

func getFederatedIdentityCredential(tx *gorm.DB, clientID string) (*types.Credential, error) {
	var cred types.Credential

	err := tx.First(&cred, "kind = ? AND identifier = ?", types.CredentialFederatedIdentity, clientID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrFederatedIdentityNotFound
	}

	if err != nil {
		return nil, err
	}

	return &cred, nil
}

// GetFederatedIdentity returns a federated identity by its client id.
func (hsdb *HSDatabase) GetFederatedIdentity(clientID string) (*types.FederatedIdentity, error) {
	cred, err := getFederatedIdentityCredential(hsdb.DB, clientID)
	if err != nil {
		return nil, err
	}

	return credentialToFederatedIdentity(cred), nil
}

// ExchangeFederatedToken mints an access token with clientID's scopes and tags if admit accepts the identity as stored when the token is saved.
func (hsdb *HSDatabase) ExchangeFederatedToken(
	clientID string,
	admit func(*types.FederatedIdentity) error,
	expiration *time.Time,
) (string, *types.OAuthAccessToken, error) {
	var (
		tokenStr string
		cred     *types.Credential
	)

	err := hsdb.Write(func(tx *gorm.DB) error {
		fiCred, err := getFederatedIdentityCredential(tx.Clauses(clause.Locking{Strength: clause.LockingStrengthShare}), clientID)
		if err != nil {
			return err
		}

		fi := credentialToFederatedIdentity(fiCred)

		err = admit(fi)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFederatedExchangeRefused, err)
		}

		tokenStr, cred, err = saveAccessToken(tx, clientID, fi.Scopes, fi.Tags, expiration)

		return err
	})
	if err != nil {
		return "", nil, err
	}

	return tokenStr, credentialToOAuthAccessToken(cred), nil
}

// ListFederatedIdentities returns every federated identity.
func (hsdb *HSDatabase) ListFederatedIdentities() ([]types.FederatedIdentity, error) {
	var creds []types.Credential

	err := hsdb.DB.Where("kind = ?", types.CredentialFederatedIdentity).Order("id").Find(&creds).Error
	if err != nil {
		return nil, err
	}

	fis := make([]types.FederatedIdentity, 0, len(creds))
	for i := range creds {
		fis = append(fis, *credentialToFederatedIdentity(&creds[i]))
	}

	return fis, nil
}

// narrowsTrust reports whether update may refuse a workload cred admits, or withhold a scope or tag cred grants.
func narrowsTrust(cred *types.Credential, update *types.FederatedIdentity) bool {
	if cred.Issuer != update.Issuer || cred.Audience != update.Audience || cred.Subject != update.Subject {
		return true
	}

	for claim, pattern := range update.CustomClaimRules {
		if old, ok := cred.CustomClaimRules[claim]; !ok || old != pattern {
			return true
		}
	}

	for _, s := range cred.Scopes {
		if !scope.Grants(scope.Parse(update.Scopes), scope.Scope(s)) {
			return true
		}
	}

	for _, tag := range cred.Tags {
		if !slices.Contains(update.Tags, tag) {
			return true
		}
	}

	return false
}

// UpdateFederatedIdentity replaces clientID's settings, deleting its access tokens if the update narrows its trust; an empty audience keeps the stored one.
func (hsdb *HSDatabase) UpdateFederatedIdentity(
	clientID string,
	update types.FederatedIdentity,
) (*types.FederatedIdentity, error) {
	err := validateFederatedIdentity(&update)
	if err != nil {
		return nil, err
	}

	var cred *types.Credential

	err = hsdb.Write(func(tx *gorm.DB) error {
		cred, err = getFederatedIdentityCredential(tx.Clauses(clause.Locking{Strength: clause.LockingStrengthUpdate}), clientID)
		if err != nil {
			return err
		}

		if update.Audience == "" {
			update.Audience = cred.Audience
		}

		if narrowsTrust(cred, &update) {
			err = tx.Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, clientID).
				Delete(&types.Credential{}).Error
			if err != nil {
				return fmt.Errorf("deleting oauth access tokens: %w", err)
			}
		}

		now := time.Now().UTC()

		cred.Issuer = update.Issuer
		cred.Subject = update.Subject
		cred.Audience = update.Audience
		cred.CustomClaimRules = update.CustomClaimRules
		cred.Description = update.Description
		cred.Scopes = update.Scopes
		cred.Tags = update.Tags
		cred.UpdatedAt = &now

		return tx.Omit("Hash").Save(cred).Error
	})
	if err != nil {
		return nil, err
	}

	return credentialToFederatedIdentity(cred), nil
}

// DeleteFederatedIdentity deletes clientID's identity and every access token exchanged through it.
func (hsdb *HSDatabase) DeleteFederatedIdentity(clientID string) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		res := tx.Where("kind = ? AND identifier = ?", types.CredentialFederatedIdentity, clientID).
			Delete(&types.Credential{})
		if res.Error != nil {
			return res.Error
		}

		if res.RowsAffected == 0 {
			return ErrFederatedIdentityNotFound
		}

		err := tx.Where("kind = ? AND client_id = ?", types.CredentialOAuthToken, clientID).
			Delete(&types.Credential{}).Error
		if err != nil {
			return fmt.Errorf("deleting oauth access tokens: %w", err)
		}

		return nil
	})
}
