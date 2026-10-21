package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strconv"
	"sync"
)

// Fake is an in-memory engine for tests. It refuses passwords shorter than 10 characters and
// "password1234" (like Kanidm's quality check), and names users and groups in one namespace.
type Fake struct {
	mu      sync.Mutex
	users   map[string]*User
	pw      map[string]string
	groups  map[string]*Group
	clients map[string]*OAuth2
	secrets map[string]string
	nextID  int
	sas     map[string]*ServiceAccount
	tokens  map[string]string // service account -> its token
	// Down makes every call fail (the engine is not running).
	Down     bool
	Prepared []string // the groups Prepare was asked for
}

func NewFake() *Fake {
	return &Fake{users: map[string]*User{}, pw: map[string]string{}, groups: map[string]*Group{},
		clients: map[string]*OAuth2{}, secrets: map[string]string{}, nextID: 1879000000,
		sas: map[string]*ServiceAccount{}, tokens: map[string]string{}}
}

var errDown = &downError{}

type downError struct{}

func (*downError) Error() string { return "engine not running" }

func (f *Fake) Ready() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return errDown
	}
	return nil
}

func (f *Fake) Prepare(admin string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return errDown
	}
	f.Prepared = []string{admin}
	if f.groups[admin] == nil {
		f.nextID++
		f.groups[admin] = &Group{Name: admin, Members: []string{}, GID: f.nextID}
	}
	return nil
}

func (f *Fake) memberships(name string) []string {
	out := []string{}
	for _, g := range f.groups {
		if slices.Contains(g.Members, name) {
			out = append(out, g.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (f *Fake) userCopy(u *User) User {
	c := *u
	c.Groups = f.memberships(u.Name)
	return c
}

func (f *Fake) Users() ([]User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	out := []User{}
	for _, u := range f.users {
		out = append(out, f.userCopy(u))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) User(name string) (*User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	u := f.users[name]
	if u == nil {
		return nil, NotFound("user", name)
	}
	c := f.userCopy(u)
	return &c, nil
}

func (f *Fake) CreateUser(name, display, mail string) (*User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	if f.users[name] != nil || f.groups[name] != nil || f.sas[name] != nil {
		return nil, Exists(name)
	}
	f.nextID++
	u := &User{Name: name, DisplayName: display, Mail: mail, Enabled: true, UID: f.nextID, UUID: hex.EncodeToString([]byte(name))}
	f.users[name] = u
	c := f.userCopy(u)
	return &c, nil
}

func (f *Fake) UpdateUser(name string, display, mail *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[name]
	if u == nil {
		return NotFound("user", name)
	}
	if display != nil {
		u.DisplayName = *display
	}
	if mail != nil {
		u.Mail = *mail
	}
	return nil
}

func (f *Fake) SetEnabled(name string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[name]
	if u == nil {
		return NotFound("user", name)
	}
	u.Enabled = on
	return nil
}

func (f *Fake) DeleteUser(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users[name] == nil {
		return NotFound("user", name)
	}
	delete(f.users, name)
	delete(f.pw, name)
	for _, g := range f.groups {
		g.Members = slices.DeleteFunc(g.Members, func(m string) bool { return m == name })
	}
	return nil
}

func hashPW(p string) string { s := sha256.Sum256([]byte(p)); return hex.EncodeToString(s[:]) }

func (f *Fake) SetPassword(name, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users[name] == nil {
		return NotFound("user", name)
	}
	if len([]rune(pw)) < 10 {
		return &WeakPasswordError{"too short (at least 10 characters)"}
	}
	if pw == "password1234" {
		return &WeakPasswordError{"too easy to guess"}
	}
	f.pw[name] = hashPW(pw)
	return nil
}

func (f *Fake) CheckPassword(name, pw string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := f.users[name]
	if u == nil || !u.Enabled {
		return false, nil
	}
	return f.pw[name] != "" && f.pw[name] == hashPW(pw), nil
}

func (f *Fake) groupCopy(g *Group) Group {
	c := *g
	c.Members = slices.Clone(g.Members)
	sort.Strings(c.Members)
	return c
}

func (f *Fake) Groups() ([]Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	out := []Group{}
	for _, g := range f.groups {
		out = append(out, f.groupCopy(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) Group(name string) (*Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.groups[name]
	if g == nil {
		return nil, NotFound("group", name)
	}
	c := f.groupCopy(g)
	return &c, nil
}

func (f *Fake) CreateGroup(name, desc string) (*Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.users[name] != nil || f.groups[name] != nil {
		return nil, Exists(name)
	}
	f.nextID++
	g := &Group{Name: name, Description: desc, Members: []string{}, GID: f.nextID}
	f.groups[name] = g
	c := f.groupCopy(g)
	return &c, nil
}

func (f *Fake) UpdateGroup(name string, desc *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.groups[name]
	if g == nil {
		return NotFound("group", name)
	}
	if desc != nil {
		g.Description = *desc
	}
	return nil
}

func (f *Fake) SetMembers(group string, members []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := f.groups[group]
	if g == nil {
		return NotFound("group", group)
	}
	for _, m := range members {
		if f.users[m] == nil {
			return NotFound("user", m)
		}
	}
	g.Members = slices.Clone(members)
	return nil
}

func (f *Fake) DeleteGroup(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.groups[name] == nil {
		return NotFound("group", name)
	}
	delete(f.groups, name)
	for _, c := range f.clients {
		delete(c.ScopeMaps, name)
	}
	return nil
}

func (f *Fake) clientCopy(c *OAuth2) OAuth2 {
	o := *c
	o.RedirectURLs = slices.Clone(c.RedirectURLs)
	o.ScopeMaps = map[string][]string{}
	for k, v := range c.ScopeMaps {
		o.ScopeMaps[k] = slices.Clone(v)
	}
	return o
}

func (f *Fake) OAuth2s() ([]OAuth2, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	out := []OAuth2{}
	for _, c := range f.clients {
		out = append(out, f.clientCopy(c))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) OAuth2(name string) (*OAuth2, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[name]
	if c == nil {
		return nil, NotFound("OIDC client", name)
	}
	o := f.clientCopy(c)
	return &o, nil
}

func (f *Fake) CreateOAuth2(c OAuth2) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients[c.Name] != nil || f.users[c.Name] != nil || f.groups[c.Name] != nil {
		return Exists(c.Name)
	}
	n := f.clientCopy(&c)
	n.PKCE = true
	f.clients[c.Name] = &n
	f.secrets[c.Name] = "secret-" + c.Name
	return nil
}

func (f *Fake) UpdateOAuth2(name string, display, landing *string, redirects []string, pkce *bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[name]
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
	return nil
}

func (f *Fake) SetScopeMap(name, group string, scopes []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	if f.groups[group] == nil && group != AllPersons {
		return NotFound("group", group)
	}
	c.ScopeMaps[group] = slices.Clone(scopes)
	return nil
}

func (f *Fake) DeleteScopeMap(name, group string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	delete(c.ScopeMaps, group)
	return nil
}

func (f *Fake) OAuth2Secret(name string, reset bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients[name] == nil {
		return "", NotFound("OIDC client", name)
	}
	if reset {
		f.secrets[name] += "x"
	}
	return f.secrets[name], nil
}

func (f *Fake) SetShortName(name string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.clients[name]
	if c == nil {
		return NotFound("OIDC client", name)
	}
	c.ShortName = on
	return nil
}

func (f *Fake) DeleteOAuth2(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients[name] == nil {
		return NotFound("OIDC client", name)
	}
	delete(f.clients, name)
	return nil
}

func (f *Fake) ServiceAccounts() ([]ServiceAccount, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return nil, errDown
	}
	out := []ServiceAccount{}
	for _, sa := range f.sas {
		c := *sa
		c.Groups = slices.Clone(sa.Groups)
		if f.tokens[sa.Name] != "" {
			c.Tokens = 1
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (f *Fake) CreateServiceAccount(name, display string, groups []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Down {
		return errDown
	}
	if f.users[name] != nil || f.groups[name] != nil || f.sas[name] != nil {
		return Exists(name)
	}
	f.nextID++
	g := slices.Clone(groups)
	sort.Strings(g)
	f.sas[name] = &ServiceAccount{Name: name, DisplayName: display, UUID: "sa-" + name, Groups: g}
	return nil
}

func (f *Fake) DeleteServiceAccount(name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sas[name] == nil {
		return NotFound("service account", name)
	}
	delete(f.sas, name)
	delete(f.tokens, name)
	return nil
}

func (f *Fake) NewAPIToken(name, label string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sas[name] == nil {
		return "", NotFound("service account", name)
	}
	f.nextID++
	sum := sha256.Sum256([]byte(name + label + strconv.Itoa(f.nextID)))
	f.tokens[name] = "eyJ." + hex.EncodeToString(sum[:]) + ".fake"
	return f.tokens[name], nil
}

// Token is a service account's current token (tests).
func (f *Fake) Token(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokens[name]
}
