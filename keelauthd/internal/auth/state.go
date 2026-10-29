// Package auth is keelauthd itself: its data (state.json), bringing up Kanidm and FreeRADIUS,
// the API, the web page's sessions and MCP. docs/02-keelauthd.md is the specification. All
// system access goes through sys.Sys, all account access through engine.Engine.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"

	"keelauth/internal/sys"
)

const (
	DataDir        = "/data/keelauth"
	Socket         = "/var/run/keelauthd.sock"
	AdminGroup     = "keelauth-admins"
	BindAccount    = "keelauth-ldap" // the read-only LDAP bind account for devices
	DefaultDomain  = "keelauth.internal"
	DefaultHTTPS   = ":443"
	DefaultHTTP    = ":80" // redirects to DefaultHTTPS (server.go)
	DefaultLDAP    = 636
	KanidmPort     = 8443
	RadiusPort     = 1812
	DefaultKeep    = 14
	statePerm      = 0o600
	stateFile      = "state.json"
	masterKeyFile  = "master.key"
	stateVersion   = 1
	tokenPrefix    = "kat_" // MCP tokens
	syncKeyPrefix  = "kas_" // keelNAS sync keys
	apiKeyPrefix   = "kap_" // API keys of other systems (tokens.go)
	sealedAdminKey = "idm_admin"
)

// UserData is what keelauthd keeps of a user beside the engine: the NT hash (sealed),
// when the password was set, "must change".
type UserData struct {
	NT         string `json:"nt,omitempty"` // sealed NT hash
	SetAt      string `json:"password_set_at,omitempty"`
	MustChange bool   `json:"must_change,omitempty"`
}

// RadiusClient is an AP or VPN gateway allowed to ask FreeRADIUS.
type RadiusClient struct {
	Name    string `json:"name"`
	Address string `json:"address"` // IP or CIDR
	Secret  string `json:"secret"`  // sealed
}

// Radius is the RADIUS settings.
type Radius struct {
	Group   string         `json:"group"` // only its members may use RADIUS; "" = every enabled user
	Clients []RadiusClient `json:"clients"`
	Local   string         `json:"local"` // sealed secret of the 127.0.0.1 client (self-test)
}

// Token is an MCP token, a sync key or an API key: only its SHA-256 is kept. Scope is the
// API key's ("users" or "admin", tokens.go).
type Token struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Hash     string `json:"hash"`
	Created  string `json:"created"`
	LastUsed string `json:"last_used,omitempty"`
	Scope    string `json:"scope,omitempty"`
}

// State is keelauthd's own data. Accounts themselves are in the engine.
type State struct {
	Version int `json:"version"`
	// Key: the internal link key. Only read from old state.json files (keelauthd before the
	// master key was wrapped kept the seed's key here): the seed carries it, and on the data
	// disk it would open master.wrap. Cleared at the start (masterkey.go).
	Key         string               `json:"key,omitempty"`
	Listen      string               `json:"listen"`       // internal link HTTP listener; "" = none
	HTTPSListen string               `json:"https_listen"` // the LAN web page
	Domain      string               `json:"domain"`       // Kanidm's domain, fixed at the first start
	LDAPPort    int                  `json:"ldap_port"`
	Admin       string               `json:"idm_admin,omitempty"` // sealed idm_admin password
	Users       map[string]*UserData `json:"users"`
	Radius      Radius               `json:"radius"`
	BindPW      string               `json:"ldap_bind,omitempty"` // sealed password of BindAccount
	Tokens      []Token              `json:"tokens"`
	SyncKeys    []Token              `json:"sync_keys"`
	APIKeys     []Token              `json:"api_keys"`
	Revision    int64                `json:"revision"`
	BackupKeep  int                  `json:"backup_keep"`
	LastBackup  string               `json:"last_backup,omitempty"`
	// Timezone: what the page shows times in when keelAuth runs standalone (keel's own zone
	// otherwise, keelOS docs/47); "" = UTC.
	Timezone string `json:"timezone,omitempty"`
	// OIDCRoles: per SSO application, what its groups mean there, as the application told us
	// (keelOS: keel-admins = admin…, PUT /v1/oidc/{name}/roles); the page shows them and offers
	// to make the missing groups
	OIDCRoles map[string]OIDCRoles `json:"oidc_roles,omitempty"`
	// Brand: the company's own name and logo on the page (brand.go): the name per language
	// (zh, en, ja; one left empty shows the first that is set), the logo file and its type.
	Brand Brand `json:"brand,omitempty"`
	// Devices: LDAP device accounts (Kanidm service accounts with a read-only API token as
	// their password, devices.go); the token itself is only in Kanidm (as its hash) and shown once
	Devices []Device `json:"devices,omitempty"`
}

// Device is one LDAP device account.
type Device struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Created     string `json:"created"`
	PasswordAt  string `json:"password_set_at"`
}

// OIDCRoles is one application's group meanings.
type OIDCRoles struct {
	By    string            `json:"by"`    // who said so ("keelOS")
	Roles map[string]string `json:"roles"` // group -> what it may do there
}

func (s *State) normalize() {
	if s.Version == 0 {
		s.Version = stateVersion
	}
	if s.HTTPSListen == "" {
		s.HTTPSListen = DefaultHTTPS
	}
	if s.LDAPPort == 0 {
		s.LDAPPort = DefaultLDAP
	}
	if s.Users == nil {
		s.Users = map[string]*UserData{}
	}
	if s.Radius.Clients == nil {
		s.Radius.Clients = []RadiusClient{}
	}
	if s.Tokens == nil {
		s.Tokens = []Token{}
	}
	if s.SyncKeys == nil {
		s.SyncKeys = []Token{}
	}
	if s.APIKeys == nil {
		s.APIKeys = []Token{}
	}
	if s.BackupKeep <= 0 {
		s.BackupKeep = DefaultKeep
	}
}

// Clone is a deep copy, so a change can be prepared and thrown away.
func (s *State) Clone() *State {
	c := *s
	c.Users = map[string]*UserData{}
	for k, v := range s.Users {
		u := *v
		c.Users[k] = &u
	}
	c.Radius.Clients = slices.Clone(s.Radius.Clients)
	c.Tokens = slices.Clone(s.Tokens)
	c.SyncKeys = slices.Clone(s.SyncKeys)
	c.APIKeys = slices.Clone(s.APIKeys)
	c.Devices = slices.Clone(s.Devices)
	if s.OIDCRoles != nil {
		c.OIDCRoles = map[string]OIDCRoles{}
		for k, v := range s.OIDCRoles {
			r := OIDCRoles{By: v.By, Roles: map[string]string{}}
			for g, x := range v.Roles {
				r.Roles[g] = x
			}
			c.OIDCRoles[k] = r
		}
	}
	c.normalize()
	return &c
}

func (s *State) user(name string) *UserData {
	u := s.Users[name]
	if u == nil {
		u = &UserData{}
		s.Users[name] = u
	}
	return u
}

func (s *State) radiusClient(name string) *RadiusClient {
	for i := range s.Radius.Clients {
		if s.Radius.Clients[i].Name == name {
			return &s.Radius.Clients[i]
		}
	}
	return nil
}

// Marshal is state.json's text.
func (s *State) Marshal() []byte {
	b, _ := json.MarshalIndent(s, "", "  ")
	return append(b, '\n')
}

// ParseState reads state.json's text.
func ParseState(b []byte) (*State, error) {
	st := &State{}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	st.normalize()
	return st, nil
}

// LoadState reads state.json in dir; a missing file is a new state.
func LoadState(sy sys.Sys, dir string) (st *State, created bool, err error) {
	p := filepath.Join(dir, stateFile)
	b, err := sy.ReadFile(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		st, created = &State{}, true
	case err != nil:
		return nil, false, err
	default:
		if st, err = ParseState(b); err != nil {
			return nil, false, fmt.Errorf("%s: %v", p, err)
		}
	}
	st.normalize()
	return st, created, nil
}

// SaveState writes state.json atomically, root only.
func SaveState(sy sys.Sys, dir string, st *State) error {
	return sy.WriteFile(filepath.Join(dir, stateFile), st.Marshal(), statePerm)
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidName: lower-case letters, digits, - and _, a letter first, at most 32.
func ValidName(n string) bool { return nameRE.MatchString(n) }

// reserved names: the engine's own accounts and keelAuth's.
func reserved(n string) bool {
	switch n {
	case "admin", "idm_admin", "anonymous", "system", "dn", BindAccount:
		return true
	}
	return len(n) > 4 && n[:4] == "idm_"
}
