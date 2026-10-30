package engine

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// Native is keelauthd's own account store (docs/01 "2026-10-30 晚：重新考虑需求"): the people,
// groups, OIDC clients and device accounts of one company in one JSON file, passwords as
// PBKDF2-SHA256 (a PHC string other software, Stalwart for one, verifies as it is). No
// Kanidm. It is the core every module (LDAP, OIDC, RADIUS) reads from; what keelauthd keeps
// beside the engine (NT hashes, "must change", access rights) stays in state.json.
//
// Names of users, groups, clients and device accounts share one namespace. Nothing here
// knows about sealing except the OIDC client secrets, which go through Seal/Open when set
// (keelauthd's master key): everything else in the file is a hash or public.
type Native struct {
	mu   sync.Mutex
	path string // "" = memory only (tests)
	d    nativeData
	// Seal / Open protect the OIDC client secrets in the file (nil: kept as they are).
	Seal func(string) string
	Open func(string) (string, error)
	// Policy is the password rule in force (SetPolicy; the zero value = 15, strict).
	policy Policy
}

// Policy is a password rule: the least length and how strict beyond it ("strict", "normal",
// "length"; docs/02 §3.14).
type Policy struct {
	MinLength int
	Strength  string
}

type nativeUser struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Mail        string `json:"mail,omitempty"`
	Enabled     bool   `json:"enabled"`
	UID         int    `json:"uid"`
	UUID        string `json:"uuid"`
	PW          string `json:"pw,omitempty"` // PHC string (HashPassword); "" = no password yet
}

type nativeGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"` // users and groups (nesting)
	GID         int      `json:"gid"`
}

type nativeSA struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	UUID        string   `json:"uuid"`
	Groups      []string `json:"groups"`
	TokenHash   string   `json:"token_hash,omitempty"` // SHA-256 (hex) of the current token
}

type nativeData struct {
	Version int                     `json:"version"`
	NextID  int                     `json:"next_id"`
	Users   map[string]*nativeUser  `json:"users"`
	Groups  map[string]*nativeGroup `json:"groups"`
	Clients map[string]*OAuth2      `json:"clients"`
	Secrets map[string]string       `json:"secrets"` // client -> secret (sealed when Seal is set)
	SAs     map[string]*nativeSA    `json:"service_accounts"`
}

const (
	nativeVersion = 1
	firstID       = 1879000000
	tokenPrefix   = "kad_" // device tokens (LDAP binds)
)

// NewNative opens (or starts) the store at path; "" keeps everything in memory.
func NewNative(path string) (*Native, error) {
	n := &Native{path: path}
	n.d = nativeData{Version: nativeVersion, NextID: firstID, Users: map[string]*nativeUser{}, Groups: map[string]*nativeGroup{},
		Clients: map[string]*OAuth2{}, Secrets: map[string]string{}, SAs: map[string]*nativeSA{}}
	if path != "" {
		b, err := os.ReadFile(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, err
		default:
			if err := json.Unmarshal(b, &n.d); err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			n.d.fix()
		}
	}
	return n, nil
}

func (d *nativeData) fix() {
	if d.Version == 0 {
		d.Version = nativeVersion
	}
	if d.NextID < firstID {
		d.NextID = firstID
	}
	if d.Users == nil {
		d.Users = map[string]*nativeUser{}
	}
	if d.Groups == nil {
		d.Groups = map[string]*nativeGroup{}
	}
	if d.Clients == nil {
		d.Clients = map[string]*OAuth2{}
	}
	if d.Secrets == nil {
		d.Secrets = map[string]string{}
	}
	if d.SAs == nil {
		d.SAs = map[string]*nativeSA{}
	}
	for _, g := range d.Groups {
		if g.Members == nil {
			g.Members = []string{}
		}
	}
	for _, c := range d.Clients {
		if c.ScopeMaps == nil {
			c.ScopeMaps = map[string][]string{}
		}
		if c.RedirectURLs == nil {
			c.RedirectURLs = []string{}
		}
	}
}

// save writes the file atomically (0600). Memory only: nothing to do.
func (n *Native) save() error {
	if n.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(&n.d, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(n.path), "."+filepath.Base(n.path)+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, n.path)
}

// Path is the store's file ("" in memory).
func (n *Native) Path() string { return n.path }

// SetPolicy sets the password rule (keelauthd: from the settings).
func (n *Native) SetPolicy(p Policy) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.policy = p
}

func (n *Native) nextID() int { n.d.NextID++; return n.d.NextID }

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func (n *Native) taken(name string) bool {
	return n.d.Users[name] != nil || n.d.Groups[name] != nil || n.d.Clients[name] != nil || n.d.SAs[name] != nil
}

func (n *Native) Ready() error { return nil }

// Prepare: the admin group exists.
func (n *Native) Prepare(admin string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.Groups[admin] == nil {
		if n.taken(admin) {
			return Exists(admin)
		}
		n.d.Groups[admin] = &nativeGroup{Name: admin, Description: "keelAuth administrators", Members: []string{}, GID: n.nextID()}
		return n.save()
	}
	return nil
}

// ---- users ----

func (n *Native) memberships(name string) []string {
	out := []string{}
	for _, g := range n.d.Groups {
		if slices.Contains(g.Members, name) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (n *Native) userOut(u *nativeUser) User {
	return User{Name: u.Name, DisplayName: u.DisplayName, Mail: u.Mail, Enabled: u.Enabled, Groups: n.memberships(u.Name), UID: u.UID, UUID: u.UUID}
}

func (n *Native) Users() ([]User, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []User{}
	for _, u := range n.d.Users {
		out = append(out, n.userOut(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (n *Native) User(name string) (*User, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	u := n.d.Users[name]
	if u == nil {
		return nil, NotFound("user", name)
	}
	o := n.userOut(u)
	return &o, nil
}

func (n *Native) CreateUser(name, display, mail string) (*User, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(name) {
		return nil, Exists(name)
	}
	u := &nativeUser{Name: name, DisplayName: display, Mail: mail, Enabled: true, UID: n.nextID(), UUID: newUUID()}
	n.d.Users[name] = u
	if err := n.save(); err != nil {
		delete(n.d.Users, name)
		return nil, err
	}
	o := n.userOut(u)
	return &o, nil
}

func (n *Native) UpdateUser(name string, display, mail *string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	u := n.d.Users[name]
	if u == nil {
		return NotFound("user", name)
	}
	if display != nil {
		u.DisplayName = *display
	}
	if mail != nil {
		u.Mail = *mail
	}
	return n.save()
}

func (n *Native) SetEnabled(name string, on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	u := n.d.Users[name]
	if u == nil {
		return NotFound("user", name)
	}
	u.Enabled = on
	return n.save()
}

func (n *Native) DeleteUser(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.Users[name] == nil {
		return NotFound("user", name)
	}
	delete(n.d.Users, name)
	for _, g := range n.d.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == name })
	}
	return n.save()
}

// SetPassword checks the password against the policy and keeps its hash.
func (n *Native) SetPassword(name, pw string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	u := n.d.Users[name]
	if u == nil {
		return NotFound("user", name)
	}
	if why := CheckQuality(n.policy, name, pw); why != "" {
		return &WeakPasswordError{why}
	}
	u.PW = HashPassword(pw)
	return n.save()
}

// CheckPassword: an enabled user with this password.
func (n *Native) CheckPassword(name, pw string) (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	u := n.d.Users[name]
	if u == nil || !u.Enabled || u.PW == "" {
		return false, nil
	}
	return VerifyPassword(u.PW, pw), nil
}

// PasswordHash is a user's PHC string ("" without a password): what a mail server's own
// directory takes as the credential.
func (n *Native) PasswordHash(name string) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	if u := n.d.Users[name]; u != nil {
		return u.PW
	}
	return ""
}

// ---- groups ----

func (n *Native) groupOut(g *nativeGroup) Group {
	c := Group{Name: g.Name, Description: g.Description, Members: []string{}, MemberGroups: []string{}, GID: g.GID}
	for _, m := range g.Members {
		if n.d.Groups[m] != nil {
			c.MemberGroups = append(c.MemberGroups, m)
		} else {
			c.Members = append(c.Members, m)
		}
	}
	sort.Strings(c.Members)
	sort.Strings(c.MemberGroups)
	return c
}

func (n *Native) Groups() ([]Group, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []Group{}
	for _, g := range n.d.Groups {
		out = append(out, n.groupOut(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (n *Native) Group(name string) (*Group, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	g := n.d.Groups[name]
	if g == nil {
		return nil, NotFound("group", name)
	}
	o := n.groupOut(g)
	return &o, nil
}

func (n *Native) CreateGroup(name, desc string) (*Group, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(name) {
		return nil, Exists(name)
	}
	g := &nativeGroup{Name: name, Description: desc, Members: []string{}, GID: n.nextID()}
	n.d.Groups[name] = g
	if err := n.save(); err != nil {
		delete(n.d.Groups, name)
		return nil, err
	}
	o := n.groupOut(g)
	return &o, nil
}

func (n *Native) UpdateGroup(name string, desc *string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	g := n.d.Groups[name]
	if g == nil {
		return NotFound("group", name)
	}
	if desc != nil {
		g.Description = *desc
	}
	return n.save()
}

func (n *Native) SetMembers(group string, members []string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	g := n.d.Groups[group]
	if g == nil {
		return NotFound("group", group)
	}
	for _, m := range members {
		if n.d.Users[m] == nil && n.d.Groups[m] == nil && n.d.SAs[m] == nil {
			return NotFound("user", m)
		}
		if m == group {
			return fmt.Errorf("group %q cannot be its own member", group)
		}
	}
	ms := slices.Clone(members)
	sort.Strings(ms)
	g.Members = slices.Compact(ms)
	return n.save()
}

func (n *Native) DeleteGroup(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.Groups[name] == nil {
		return NotFound("group", name)
	}
	delete(n.d.Groups, name)
	for _, g := range n.d.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == name })
	}
	for _, c := range n.d.Clients {
		delete(c.ScopeMaps, name)
	}
	return n.save()
}

// ---- OIDC clients ----

func clientCopy(c *OAuth2) OAuth2 {
	o := *c
	o.RedirectURLs = slices.Clone(c.RedirectURLs)
	o.ScopeMaps = map[string][]string{}
	for k, v := range c.ScopeMaps {
		o.ScopeMaps[k] = slices.Clone(v)
	}
	return o
}

func (n *Native) OAuth2s() ([]OAuth2, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []OAuth2{}
	for _, c := range n.d.Clients {
		out = append(out, clientCopy(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (n *Native) OAuth2(name string) (*OAuth2, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.d.Clients[name]
	if c == nil {
		return nil, NotFound("OIDC client", name)
	}
	o := clientCopy(c)
	return &o, nil
}

func (n *Native) sealed(v string) string {
	if n.Seal != nil {
		return n.Seal(v)
	}
	return v
}

func (n *Native) opened(v string) (string, error) {
	if n.Open != nil {
		return n.Open(v)
	}
	return v, nil
}

// Secret is a new client secret: 32 random bytes, base64url.
func Secret() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func (n *Native) CreateOAuth2(c OAuth2) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(c.Name) {
		return Exists(c.Name)
	}
	o := clientCopy(&c)
	n.d.Clients[c.Name] = &o
	n.d.Secrets[c.Name] = n.sealed(Secret())
	if err := n.save(); err != nil {
		delete(n.d.Clients, c.Name)
		delete(n.d.Secrets, c.Name)
		return err
	}
	return nil
}

func (n *Native) UpdateOAuth2(name string, display, landing *string, redirects []string, pkce, rs256 *bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.d.Clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	if display != nil {
		c.DisplayName = *display
	}
	if landing != nil {
		c.LandingURL = *landing
	}
	if redirects != nil {
		c.RedirectURLs = slices.Clone(redirects)
	}
	if pkce != nil {
		c.PKCE = *pkce
	}
	if rs256 != nil {
		c.RS256 = *rs256
	}
	return n.save()
}

func (n *Native) SetScopeMap(name, group string, scopes []string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.d.Clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	if n.d.Groups[group] == nil && group != AllPersons {
		return NotFound("group", group)
	}
	c.ScopeMaps[group] = slices.Clone(scopes)
	return n.save()
}

func (n *Native) DeleteScopeMap(name, group string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.d.Clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	delete(c.ScopeMaps, group)
	return n.save()
}

func (n *Native) OAuth2Secret(name string, reset bool) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.Clients[name] == nil {
		return "", NotFound("OIDC client", name)
	}
	if reset || n.d.Secrets[name] == "" {
		n.d.Secrets[name] = n.sealed(Secret())
		if err := n.save(); err != nil {
			return "", err
		}
	}
	return n.opened(n.d.Secrets[name])
}

func (n *Native) SetShortName(name string, on bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	c := n.d.Clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	c.ShortName = on
	return n.save()
}

func (n *Native) DeleteOAuth2(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.Clients[name] == nil {
		return NotFound("OIDC client", name)
	}
	delete(n.d.Clients, name)
	delete(n.d.Secrets, name)
	return n.save()
}

// ---- service (device) accounts ----

func (n *Native) ServiceAccounts() ([]ServiceAccount, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := []ServiceAccount{}
	for _, sa := range n.d.SAs {
		c := ServiceAccount{Name: sa.Name, DisplayName: sa.DisplayName, UUID: sa.UUID, Groups: slices.Clone(sa.Groups)}
		if sa.TokenHash != "" {
			c.Tokens = 1
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (n *Native) CreateServiceAccount(name, display string, groups []string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.taken(name) {
		return Exists(name)
	}
	g := slices.Clone(groups)
	sort.Strings(g)
	n.d.SAs[name] = &nativeSA{Name: name, DisplayName: display, UUID: newUUID(), Groups: g}
	if err := n.save(); err != nil {
		delete(n.d.SAs, name)
		return err
	}
	return nil
}

func (n *Native) DeleteServiceAccount(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.d.SAs[name] == nil {
		return NotFound("service account", name)
	}
	delete(n.d.SAs, name)
	for _, g := range n.d.Groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == name })
	}
	return n.save()
}

func tokenHash(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

// NewAPIToken gives the account a new token (kad_…, shown once) and forgets the old one.
func (n *Native) NewAPIToken(name, label string) (string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	sa := n.d.SAs[name]
	if sa == nil {
		return "", NotFound("service account", name)
	}
	var b [24]byte
	rand.Read(b[:])
	t := tokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	sa.TokenHash = tokenHash(t)
	if err := n.save(); err != nil {
		return "", err
	}
	return t, nil
}

// CheckToken: the service account's current token (an LDAP bind of a device).
func (n *Native) CheckToken(name, token string) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	sa := n.d.SAs[name]
	if sa == nil || sa.TokenHash == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(sa.TokenHash), []byte(tokenHash(token))) == 1
}

// ---- passwords ----

const (
	pbkdfIter = 600000 // OWASP 2023 for PBKDF2-HMAC-SHA256
	pbkdfLen  = 32
)

// HashPassword is the PHC string of a new PBKDF2-SHA256 hash:
// $pbkdf2-sha256$i=600000$<salt>$<hash>, salt and hash in PHC base64 (no padding).
func HashPassword(pw string) string {
	var salt [16]byte
	rand.Read(salt[:])
	k, _ := pbkdf2.Key(sha256.New, pw, salt[:], pbkdfIter, pbkdfLen)
	return fmt.Sprintf("$pbkdf2-sha256$i=%d$%s$%s", pbkdfIter,
		base64.RawStdEncoding.EncodeToString(salt[:]), base64.RawStdEncoding.EncodeToString(k))
}

// VerifyPassword checks pw against a PHC string HashPassword made.
func VerifyPassword(phc, pw string) bool {
	f := strings.Split(phc, "$")
	if len(f) != 5 || f[0] != "" || f[1] != "pbkdf2-sha256" || !strings.HasPrefix(f[2], "i=") {
		return false
	}
	iter, err := strconv.Atoi(f[2][2:])
	if err != nil || iter < 1000 || iter > 10000000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(f[3])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(f[4])
	if err != nil || len(want) == 0 {
		return false
	}
	k, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(k, want) == 1
}

// DefaultMinLength is the password length without a policy (and the length check is all
// the default policy does: docs/01, "密码不折磨人").
const DefaultMinLength = 8

// CheckQuality says why a password is refused for name under the policy ("" = fine):
// too short; with "normal" and "strict" also the user's name in it, a common password, one
// character repeated or a keyboard run; with "strict" also fewer than three kinds of
// characters unless it is 20 or longer.
func CheckQuality(p Policy, name, pw string) string {
	min := p.MinLength
	if min <= 0 {
		min = DefaultMinLength
	}
	runes := []rune(pw)
	if len(runes) < min {
		return fmt.Sprintf("too short (at least %d characters)", min)
	}
	if p.Strength == "length" || p.Strength == "" { // the default: the length is all
		return ""
	}
	low := strings.ToLower(pw)
	if n := strings.ToLower(name); len(n) >= 3 && strings.Contains(low, n) {
		return "contains the user name"
	}
	if commonPassword(low) {
		return "too easy to guess (a common password)"
	}
	if p.Strength == "strict" && len(runes) < 20 && charKinds(runes) < 3 {
		return "use at least three kinds of characters (lower case, upper case, digits, symbols), or 20 characters or more"
	}
	return ""
}

func charKinds(rs []rune) int {
	var lower, upper, digit, other bool
	for _, r := range rs {
		switch {
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			n++
		}
	}
	return n
}

// commonPassword: the password (lower case) is on the short list of the most used ones, or
// is one of them with digits or punctuation around, or one character over and over, or a
// run along the keyboard / the alphabet / the digits.
func commonPassword(low string) bool {
	core := strings.Trim(low, "0123456789!@#$%^&*()_+-=.,;:?/ ")
	if core == "" {
		return true
	}
	if slices.Contains(commonList, low) || slices.Contains(commonList, core) {
		return true
	}
	same := true
	for i := 1; i < len(low); i++ {
		if low[i] != low[0] {
			same = false
			break
		}
	}
	if same {
		return true
	}
	for _, run := range []string{"abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba", "0123456789", "9876543210",
		"qwertyuiop", "asdfghjkl", "zxcvbnm", "1qaz2wsx3edc4rfv5tgb6yhn7ujm", "qazwsxedcrfvtgbyhnujm"} {
		if len(core) >= 6 && strings.Contains(run, core) {
			return true
		}
	}
	return false
}

var commonList = []string{
	"password", "passw0rd", "p@ssw0rd", "p@ssword", "passwort", "passwords", "password1", "password123", "password1234",
	"letmein", "welcome", "welcome1", "admin", "administrator", "root", "toor", "user", "guest", "test", "testtest",
	"qwerty", "qwertyuiop", "qwerty123", "abc123", "abcd1234", "abcdefgh", "iloveyou", "monkey", "dragon", "sunshine",
	"princess", "football", "baseball", "soccer", "master", "shadow", "superman", "batman", "trustno1", "whatever",
	"login", "secret", "changeme", "default", "freedom", "hello", "hello123", "computer", "internet", "mustang",
	"michael", "jennifer", "charlie", "jordan", "hunter", "ranger", "thomas", "robert", "daniel", "andrew",
	"keelauth", "keelos", "keelnas", "keelmail", "keel", "company", "office", "windows", "linux", "freebsd",
	"starwars", "pokemon", "cheese", "summer", "winter", "spring", "autumn", "flower", "killer", "ashley",
	"bailey", "access", "zaq1zaq1", "1q2w3e4r", "1q2w3e4r5t", "1qaz2wsx", "qazwsx", "asdfgh", "zxcvbn", "112233",
	"123123", "123321", "123456", "1234567", "12345678", "123456789", "1234567890", "11111111", "00000000",
	"666666", "888888", "654321", "987654321", "aaaaaaaa", "password!", "password#1", "adminadmin", "letmein1",
}

// itoa for messages.
func itoa(n int) string { return strconv.Itoa(n) }

// Export is the store as a backup carries it (accounts.json's text).
func (n *Native) Export() []byte {
	n.mu.Lock()
	defer n.mu.Unlock()
	b, _ := json.MarshalIndent(&n.d, "", "  ")
	return append(b, '\n')
}

// Import replaces the store with a backup's text. The OIDC client secrets in it are sealed
// under the backup's key (from): they are resealed with to when both are given.
func (n *Native) Import(b []byte, from, to interface {
	Seal(string) string
	Open(string) (string, error)
}) error {
	var d nativeData
	if err := json.Unmarshal(b, &d); err != nil {
		return err
	}
	d.fix()
	if from != nil && to != nil {
		for k, v := range d.Secrets {
			p, err := from.Open(v)
			if err != nil {
				return fmt.Errorf("client %s: %v", k, err)
			}
			d.Secrets[k] = to.Seal(p)
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	old := n.d
	n.d = d
	if err := n.save(); err != nil {
		n.d = old
		return err
	}
	return nil
}

// FindToken is the device account whose current token this is ("" when none): a "dn=token"
// LDAP bind names no account, the token does.
func (n *Native) FindToken(token string) (string, bool) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return "", false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	h := tokenHash(token)
	for name, sa := range n.d.SAs {
		if sa.TokenHash != "" && subtle.ConstantTimeCompare([]byte(sa.TokenHash), []byte(h)) == 1 {
			return name, true
		}
	}
	return "", false
}
