// Package engine is the account engine behind keelauthd: Kanidm in the VM (kanidm.go), an
// in-memory fake for tests (fake.go). keelauthd keeps what the engine cannot (the NT hash,
// "must change") itself.
package engine

import (
	"errors"
	"fmt"
)

// User is a person in the engine.
type User struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Mail        string   `json:"mail"`
	Enabled     bool     `json:"enabled"`
	Groups      []string `json:"groups"` // direct memberships, keelAuth's own groups only
	UID         int      `json:"uid"`
	UUID        string   `json:"uuid"`
}

// Group is a group in the engine (only the ones keelAuth made; built-in engine groups are left out).
type Group struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	GID         int      `json:"gid"`
}

// OAuth2 is an OIDC client (Kanidm calls it an OAuth2 resource server).
type OAuth2 struct {
	Name         string              `json:"name"`
	DisplayName  string              `json:"display_name"`
	LandingURL   string              `json:"landing_url"`
	RedirectURLs []string            `json:"redirect_urls"`
	ScopeMaps    map[string][]string `json:"scope_maps"` // group -> scopes
	PKCE         bool                `json:"pkce"`
	// ShortName: preferred_username is the bare name (alice), not the SPN (alice@domain)
	ShortName bool `json:"short_name"`
}

// ServiceAccount is an account for a device or program, not a person (Kanidm's service
// account). keelAuth's LDAP device accounts are these: they bind with an API token, which
// (unlike a password bind, docs/02 section 7.10) may read mail.
type ServiceAccount struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	UUID        string   `json:"uuid"`
	Groups      []string `json:"groups"` // direct memberships (the engine's read groups)
	Tokens      int      `json:"tokens"` // API tokens it has
}

// Engine is what keelauthd needs from the account engine.
type Engine interface {
	// Ready reports whether the engine answers (and keelauthd can log in to it).
	Ready() error
	// Prepare sets the engine up the way keelAuth uses it (idempotent): password-only
	// credentials allowed, the admin group exists, anonymous LDAP reads off.
	Prepare(adminGroup string) error

	Users() ([]User, error)
	User(name string) (*User, error)
	CreateUser(name, displayName, mail string) (*User, error)
	UpdateUser(name string, displayName, mail *string) error
	SetEnabled(name string, enabled bool) error
	DeleteUser(name string) error
	// SetPassword sets both credentials: the primary one (the engine's own login, SSO) and the
	// unix one (LDAP binds). A password the engine refuses is a *WeakPasswordError.
	SetPassword(name, password string) error
	// CheckPassword reports whether password is name's (unix credential, as LDAP checks it).
	CheckPassword(name, password string) (bool, error)

	Groups() ([]Group, error)
	Group(name string) (*Group, error)
	CreateGroup(name, description string) (*Group, error)
	UpdateGroup(name string, description *string) error
	SetMembers(group string, members []string) error
	DeleteGroup(name string) error

	OAuth2s() ([]OAuth2, error)
	OAuth2(name string) (*OAuth2, error)
	CreateOAuth2(c OAuth2) error
	UpdateOAuth2(name string, displayName, landing *string, redirects []string, pkce *bool) error
	SetScopeMap(name, group string, scopes []string) error
	DeleteScopeMap(name, group string) error
	OAuth2Secret(name string, reset bool) (string, error)
	DeleteOAuth2(name string) error
	// SetShortName: the client's preferred_username without @domain (most applications take it
	// as the user name as it is)
	SetShortName(name string, on bool) error

	ServiceAccounts() ([]ServiceAccount, error)
	// CreateServiceAccount makes one and puts it into the given (engine) groups.
	CreateServiceAccount(name, displayName string, groups []string) error
	DeleteServiceAccount(name string) error
	// NewAPIToken revokes the account's tokens and makes a new read-only one without expiry.
	NewAPIToken(name, label string) (string, error)
}

// Kanidm's groups whose members read what LDAP clients need: mail addresses, and the POSIX
// attributes (uidnumber, gidnumber, home directory; group searches by posixgroup).
const (
	MailRead = "idm_account_mail_read"
	UnixRead = "idm_unix_authentication_read"
)

// AllPersons is the engine's group of every person: the scope map for "all users".
const AllPersons = "idm_all_persons"

// ErrNotFound: no such user, group or client.
var ErrNotFound = errors.New("not found")

// ErrExists: the name is taken.
var ErrExists = errors.New("already exists")

// WeakPasswordError is a password the engine refused, with its reason in words.
type WeakPasswordError struct{ Reason string }

func (e *WeakPasswordError) Error() string { return "password refused: " + e.Reason }

// NotFound wraps ErrNotFound with what was looked for.
func NotFound(kind, name string) error { return fmt.Errorf("no %s %q: %w", kind, name, ErrNotFound) }

// Exists wraps ErrExists with the name.
func Exists(name string) error { return fmt.Errorf("%q: %w", name, ErrExists) }
