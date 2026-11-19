package types

import (
	"strings"
	"time"
)

// SplitClaimPath splits a dotted custom claim rule path; a double-quoted segment may hold dots.
func SplitClaimPath(path string) []string {
	var (
		segs   []string
		cur    strings.Builder
		quoted bool
	)

	for _, r := range path {
		switch {
		case r == '"':
			quoted = !quoted
		case r == '.' && !quoted:
			segs = append(segs, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}

	return append(segs, cur.String())
}

// FederatedIdentity trades a matching OIDC token from Issuer for an access token carrying Scopes and Tags.
type FederatedIdentity struct {
	ID       uint64
	ClientID string

	Issuer           string
	Subject          string
	Audience         string
	CustomClaimRules map[string]string

	Description string

	Scopes []string
	Tags   []string

	// UserID records who created the identity; cleared when the user is deleted.
	UserID *uint

	CreatedAt *time.Time
	UpdatedAt *time.Time
}
