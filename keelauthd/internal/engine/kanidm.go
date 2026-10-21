package engine

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Kanidm drives Kanidm (1.10) over its REST API as idm_admin (docs/01-plan.md D0 lists the
// calls). It logs in with idm_admin's password (Password) and keeps the session token until it
// expires or a call answers 401.
type Kanidm struct {
	URL      string // https://127.0.0.1:8443
	Domain   string // for SPNs: name@domain
	Password func() (string, error)
	// Recover gives idm_admin a new password (kanidmd recover-account) when the one Password
	// returns no longer works; nil = never.
	Recover func() error

	client *http.Client
	mu     sync.Mutex
	token  string
	until  time.Time
}

// NewKanidm talks to Kanidm on the loopback address; its certificate is keelAuth's own and
// the connection never leaves the VM, so the chain is not checked.
func NewKanidm(u, domain string, pw func() (string, error)) *Kanidm {
	tr := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	return &Kanidm{URL: strings.TrimRight(u, "/"), Domain: domain, Password: pw,
		client: &http.Client{Transport: tr, Timeout: 60 * time.Second}}
}

// apiErr is an answer other than 2xx.
type apiErr struct {
	Status int
	Body   string
}

func (e *apiErr) Error() string {
	return fmt.Sprintf("kanidm: %d %s", e.Status, strings.TrimSpace(e.Body))
}

func (k *Kanidm) raw(method, path string, hdr map[string]string, body any) (int, http.Header, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, k.URL+path, rd)
	if err != nil {
		return 0, nil, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for h, v := range hdr {
		req.Header.Set(h, v)
	}
	resp, err := k.client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("kanidm: %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return resp.StatusCode, resp.Header, b, err
}

// login logs in as idm_admin; when the password is refused it recovers a new one once.
func (k *Kanidm) login() error {
	err := k.login1()
	if err != nil && k.Recover != nil && strings.Contains(err.Error(), "login failed") {
		if rerr := k.Recover(); rerr != nil {
			return fmt.Errorf("%v; recovering idm_admin: %v", err, rerr)
		}
		err = k.login1()
	}
	return err
}

// login1 runs the password authentication of idm_admin and keeps the token.
func (k *Kanidm) login1() error {
	pw, err := k.Password()
	if err != nil {
		return fmt.Errorf("idm_admin password: %v", err)
	}
	st, h, b, err := k.raw("POST", "/v1/auth", nil, map[string]any{"step": map[string]any{"init": "idm_admin"}})
	if err != nil {
		return err
	}
	if st != 200 {
		return &apiErr{st, string(b)}
	}
	sid := map[string]string{"X-KANIDM-AUTH-SESSION-ID": h.Get("X-KANIDM-AUTH-SESSION-ID")}
	if st, _, b, err = k.raw("POST", "/v1/auth", sid, map[string]any{"step": map[string]any{"begin": "password"}}); err != nil {
		return err
	} else if st != 200 {
		return &apiErr{st, string(b)}
	}
	st, _, b, err = k.raw("POST", "/v1/auth", sid, map[string]any{"step": map[string]any{"cred": map[string]any{"password": pw}}})
	if err != nil {
		return err
	}
	var r struct {
		State struct {
			Success string `json:"success"`
		} `json:"state"`
	}
	if st != 200 || json.Unmarshal(b, &r) != nil || r.State.Success == "" {
		return fmt.Errorf("kanidm: idm_admin login failed: %d %s", st, strings.TrimSpace(string(b)))
	}
	k.token = r.State.Success
	k.until = time.Now().Add(50 * time.Minute) // Kanidm's read-write sessions last an hour
	return nil
}

// do calls the API as idm_admin; out may be nil. A 401 logs in again once.
func (k *Kanidm) do(method, path string, body, out any) error {
	for try := 0; ; try++ {
		k.mu.Lock()
		if k.token == "" || time.Now().After(k.until) {
			if err := k.login(); err != nil {
				k.mu.Unlock()
				return err
			}
		}
		tok := k.token
		k.mu.Unlock()
		st, _, b, err := k.raw(method, path, map[string]string{"Authorization": "Bearer " + tok}, body)
		if err != nil {
			return err
		}
		if st == 401 && try == 0 {
			k.mu.Lock()
			k.token = ""
			k.mu.Unlock()
			continue
		}
		if st < 200 || st > 299 {
			return k.mapErr(st, b)
		}
		if out != nil && len(bytes.TrimSpace(b)) > 0 {
			return json.Unmarshal(b, out)
		}
		return nil
	}
}

func (k *Kanidm) mapErr(st int, b []byte) error {
	s := string(b)
	switch {
	case st == 404:
		return fmt.Errorf("%s: %w", strings.Trim(strings.TrimSpace(s), `"`), ErrNotFound)
	case st == 409:
		return fmt.Errorf("%s: %w", strings.TrimSpace(s), ErrExists)
	case strings.Contains(s, "passwordquality"):
		return &WeakPasswordError{qualityText(b)}
	}
	return &apiErr{st, s}
}

// qualityText puts Kanidm's password quality answer in words:
// {"passwordquality":[{"tooshort":10}]}, {"passwordquality":["badlisted"]}, …
func qualityText(b []byte) string {
	var r struct {
		Q []json.RawMessage `json:"passwordquality"`
	}
	if json.Unmarshal(b, &r) != nil || len(r.Q) == 0 {
		return strings.TrimSpace(string(b))
	}
	var out []string
	for _, q := range r.Q {
		var s string
		var m map[string]any
		switch {
		case json.Unmarshal(q, &s) == nil:
			switch s {
			case "badlisted":
				out = append(out, "too easy to guess (a common password)")
			case "dontreusepasswords":
				out = append(out, "the same as before")
			default:
				out = append(out, "too easy to guess ("+s+")")
			}
		case json.Unmarshal(q, &m) == nil:
			if n, ok := m["tooshort"]; ok {
				out = append(out, fmt.Sprintf("too short (at least %v characters)", n))
			} else if fb, ok := m["feedback"]; ok {
				out = append(out, fmt.Sprintf("too easy to guess (%v)", fb))
			} else {
				out = append(out, string(q))
			}
		default:
			out = append(out, string(q))
		}
	}
	return strings.Join(out, "; ")
}

type entry struct {
	Attrs map[string][]string `json:"attrs"`
}

func (e *entry) one(a string) string {
	if v := e.Attrs[a]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (e *entry) has(class string) bool { return slices.Contains(e.Attrs["class"], class) }

// spnName turns "bob@auth.office.lan" (or a bare name) into "bob".
func spnName(s string) string {
	n, _, _ := strings.Cut(s, "@")
	return n
}

func esc(s string) string { return url.PathEscape(s) }

// ---- preparation ----

func (k *Kanidm) Ready() error {
	var e *entry
	return k.do("GET", "/v1/group/idm_all_persons", nil, &e)
}

func (k *Kanidm) Prepare(adminGroup string) error {
	// password-only accounts (no MFA requirement) for everyone: keelAuth's users log in with a
	// password everywhere (LDAP, RADIUS and SMB cannot ask for a second factor anyway)
	var all *entry
	if err := k.do("GET", "/v1/group/idm_all_persons", nil, &all); err != nil {
		return err
	}
	if all == nil || all.one("credential_type_minimum") != "any" {
		if err := k.do("PUT", "/v1/group/idm_all_persons/_attr/credential_type_minimum", []string{"any"}, nil); err != nil {
			return fmt.Errorf("credential policy: %v", err)
		}
	}
	if g, err := k.Group(adminGroup); errors.Is(err, ErrNotFound) || (err == nil && g == nil) {
		if _, err := k.CreateGroup(adminGroup, "keelAuth administrators"); err != nil && !errors.Is(err, ErrExists) {
			return err
		}
	} else if err != nil {
		return err
	}
	// anonymous LDAP reads off: only devices that bind (keelAuth's read-only bind account) read
	var an *entry
	if err := k.do("GET", "/v1/service_account/anonymous", nil, &an); err != nil {
		return err
	}
	if an != nil && an.one("account_expire") == "" {
		if err := k.do("PUT", "/v1/service_account/anonymous/_attr/account_expire", []string{"1970-01-01T00:00:00Z"}, nil); err != nil {
			return fmt.Errorf("anonymous off: %v", err)
		}
	}
	return nil
}

// ---- users ----

// builtinGroup: the engine's own groups, never shown.
func builtinGroup(e *entry) bool {
	return e.has("builtin") || e.has("system") || e.has("dyngroup") || strings.HasPrefix(e.one("name"), "idm_")
}

func (k *Kanidm) ownGroups() (map[string]bool, error) {
	var es []entry
	if err := k.do("GET", "/v1/group", nil, &es); err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for i := range es {
		if !builtinGroup(&es[i]) {
			m[es[i].one("name")] = true
		}
	}
	return m, nil
}

func enabled(e *entry) bool {
	exp := e.one("account_expire")
	if exp == "" {
		return true
	}
	t, err := time.Parse(time.RFC3339, exp)
	return err == nil && t.After(time.Now())
}

func toUser(e *entry, own map[string]bool) User {
	u := User{Name: e.one("name"), DisplayName: e.one("displayname"), Mail: e.one("mail"), Enabled: enabled(e),
		UUID: e.one("uuid"), Groups: []string{}}
	u.UID, _ = strconv.Atoi(e.one("gidnumber"))
	for _, g := range e.Attrs["directmemberof"] {
		if n := spnName(g); own[n] {
			u.Groups = append(u.Groups, n)
		}
	}
	sort.Strings(u.Groups)
	return u
}

func (k *Kanidm) Users() ([]User, error) {
	own, err := k.ownGroups()
	if err != nil {
		return nil, err
	}
	var es []entry
	if err := k.do("GET", "/v1/person", nil, &es); err != nil {
		return nil, err
	}
	out := []User{}
	for i := range es {
		out = append(out, toUser(&es[i], own))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (k *Kanidm) User(name string) (*User, error) {
	var e *entry
	if err := k.do("GET", "/v1/person/"+esc(name), nil, &e); err != nil {
		return nil, err
	}
	if e == nil || e.one("name") == "" {
		return nil, NotFound("user", name)
	}
	own, err := k.ownGroups()
	if err != nil {
		return nil, err
	}
	u := toUser(e, own)
	return &u, nil
}

func (k *Kanidm) CreateUser(name, display, mail string) (*User, error) {
	attrs := map[string][]string{"name": {name}, "displayname": {display}}
	if mail != "" {
		attrs["mail"] = []string{mail}
	}
	if err := k.do("POST", "/v1/person", map[string]any{"attrs": attrs}, nil); err != nil {
		return nil, err
	}
	// POSIX: a uid/gid for LDAP clients (Linux, NAS) and keelNAS
	if err := k.do("POST", "/v1/person/"+esc(name)+"/_unix", map[string]any{}, nil); err != nil {
		return nil, fmt.Errorf("posix: %v", err)
	}
	return k.User(name)
}

func (k *Kanidm) setAttr(kind, name, attr string, val *string) error {
	if val == nil {
		return nil
	}
	p := "/v1/" + kind + "/" + esc(name) + "/_attr/" + attr
	if *val == "" {
		err := k.do("DELETE", p, nil, nil)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return k.do("PUT", p, []string{*val}, nil)
}

func (k *Kanidm) UpdateUser(name string, display, mail *string) error {
	if _, err := k.User(name); err != nil {
		return err
	}
	if display != nil && *display == "" {
		display = &name // Kanidm requires a display name
	}
	if err := k.setAttr("person", name, "displayname", display); err != nil {
		return err
	}
	return k.setAttr("person", name, "mail", mail)
}

func (k *Kanidm) SetEnabled(name string, on bool) error {
	if _, err := k.User(name); err != nil {
		return err
	}
	v := ""
	if !on {
		v = "1970-01-01T00:00:00Z"
	}
	return k.setAttr("person", name, "account_expire", &v)
}

func (k *Kanidm) DeleteUser(name string) error {
	return k.do("DELETE", "/v1/person/"+esc(name), nil, nil)
}

func (k *Kanidm) SetPassword(name, pw string) error {
	// the unix credential first: LDAP binds (and the quality check answers in plain JSON here)
	if err := k.do("PUT", "/v1/person/"+esc(name)+"/_unix/_credential", map[string]string{"value": pw}, nil); err != nil {
		return err
	}
	// the primary credential through an update session: Kanidm's own login (SSO)
	var start []json.RawMessage
	if err := k.do("GET", "/v1/person/"+esc(name)+"/_credential/_update", nil, &start); err != nil {
		return fmt.Errorf("credential update: %v", err)
	}
	if len(start) < 1 {
		return errors.New("credential update: no session")
	}
	tok := start[0]
	var st struct {
		CanCommit bool     `json:"can_commit"`
		Warnings  []string `json:"warnings"`
	}
	if err := k.do("POST", "/v1/credential/_update", []any{map[string]string{"password": pw}, tok}, &st); err != nil {
		return err
	}
	if !st.CanCommit {
		return fmt.Errorf("kanidm will not take the password as the primary credential: %v", st.Warnings)
	}
	return k.do("POST", "/v1/credential/_commit", tok, nil)
}

func (k *Kanidm) CheckPassword(name, pw string) (bool, error) {
	var r *struct {
		Name string `json:"name"`
	}
	err := k.do("POST", "/v1/account/"+esc(name)+"/_unix/_auth", map[string]string{"value": pw}, &r)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		var ae *apiErr
		if errors.As(err, &ae) && (ae.Status == 400 || ae.Status == 401 || ae.Status == 403) {
			return false, nil
		}
		return false, err
	}
	return r != nil && r.Name == name, nil
}

// ---- groups ----

func toGroup(e *entry) Group {
	g := Group{Name: e.one("name"), Description: e.one("description"), Members: []string{}}
	g.GID, _ = strconv.Atoi(e.one("gidnumber"))
	for _, m := range e.Attrs["member"] {
		g.Members = append(g.Members, spnName(m))
	}
	sort.Strings(g.Members)
	return g
}

func (k *Kanidm) Groups() ([]Group, error) {
	var es []entry
	if err := k.do("GET", "/v1/group", nil, &es); err != nil {
		return nil, err
	}
	out := []Group{}
	for i := range es {
		if !builtinGroup(&es[i]) {
			out = append(out, toGroup(&es[i]))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (k *Kanidm) Group(name string) (*Group, error) {
	var e *entry
	if err := k.do("GET", "/v1/group/"+esc(name), nil, &e); err != nil {
		return nil, err
	}
	if e == nil || e.one("name") == "" || builtinGroup(e) {
		return nil, NotFound("group", name)
	}
	g := toGroup(e)
	return &g, nil
}

func (k *Kanidm) CreateGroup(name, desc string) (*Group, error) {
	attrs := map[string][]string{"name": {name}}
	if desc != "" {
		attrs["description"] = []string{desc}
	}
	if err := k.do("POST", "/v1/group", map[string]any{"attrs": attrs}, nil); err != nil {
		return nil, err
	}
	if err := k.do("POST", "/v1/group/"+esc(name)+"/_unix", map[string]any{}, nil); err != nil {
		return nil, fmt.Errorf("posix: %v", err)
	}
	return k.Group(name)
}

func (k *Kanidm) UpdateGroup(name string, desc *string) error {
	if _, err := k.Group(name); err != nil {
		return err
	}
	return k.setAttr("group", name, "description", desc)
}

func (k *Kanidm) SetMembers(group string, members []string) error {
	if _, err := k.Group(group); err != nil {
		return err
	}
	if len(members) == 0 {
		err := k.do("DELETE", "/v1/group/"+esc(group)+"/_attr/member", nil, nil)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		return err
	}
	return k.do("PUT", "/v1/group/"+esc(group)+"/_attr/member", members, nil)
}

func (k *Kanidm) DeleteGroup(name string) error {
	if _, err := k.Group(name); err != nil {
		return err
	}
	return k.do("DELETE", "/v1/group/"+esc(name), nil, nil)
}

// ---- OAuth2 / OIDC ----

// scopeRE reads one value of oauth2_rs_scope_map: `office@auth.office.lan: {"email", "openid"}`.
var scopeRE = regexp.MustCompile(`^([^:]+):\s*\{(.*)\}$`)

func toOAuth2(e *entry) OAuth2 {
	c := OAuth2{Name: e.one("name"), DisplayName: e.one("displayname"), LandingURL: e.one("oauth2_rs_origin_landing"),
		RedirectURLs: slices.Clone(e.Attrs["oauth2_rs_origin"]), ScopeMaps: map[string][]string{},
		PKCE: e.one("oauth2_allow_insecure_client_disable_pkce") != "true", ShortName: e.one("oauth2_prefer_short_username") == "true"}
	if c.RedirectURLs == nil {
		c.RedirectURLs = []string{}
	}
	for _, v := range e.Attrs["oauth2_rs_scope_map"] {
		m := scopeRE.FindStringSubmatch(v)
		if m == nil {
			continue
		}
		scopes := []string{}
		for _, s := range strings.Split(m[2], ",") {
			if s = strings.Trim(strings.TrimSpace(s), `"`); s != "" {
				scopes = append(scopes, s)
			}
		}
		sort.Strings(scopes)
		c.ScopeMaps[spnName(strings.TrimSpace(m[1]))] = scopes
	}
	return c
}

func (k *Kanidm) OAuth2s() ([]OAuth2, error) {
	var es []entry
	if err := k.do("GET", "/v1/oauth2", nil, &es); err != nil {
		return nil, err
	}
	out := []OAuth2{}
	for i := range es {
		out = append(out, toOAuth2(&es[i]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (k *Kanidm) OAuth2(name string) (*OAuth2, error) {
	var e *entry
	if err := k.do("GET", "/v1/oauth2/"+esc(name), nil, &e); err != nil {
		return nil, err
	}
	if e == nil || e.one("name") == "" {
		return nil, NotFound("OIDC client", name)
	}
	c := toOAuth2(e)
	return &c, nil
}

func (k *Kanidm) CreateOAuth2(c OAuth2) error {
	attrs := map[string][]string{"name": {c.Name}, "displayname": {c.DisplayName}, "oauth2_rs_origin_landing": {c.LandingURL}}
	if err := k.do("POST", "/v1/oauth2/_basic", map[string]any{"attrs": attrs}, nil); err != nil {
		return err
	}
	if len(c.RedirectURLs) > 0 {
		if err := k.do("POST", "/v1/oauth2/"+esc(c.Name)+"/_attr/oauth2_rs_origin", c.RedirectURLs, nil); err != nil {
			k.do("DELETE", "/v1/oauth2/"+esc(c.Name), nil, nil)
			return fmt.Errorf("redirect URLs: %v", err)
		}
	}
	if !c.PKCE {
		v := false
		if err := k.UpdateOAuth2(c.Name, nil, nil, nil, &v); err != nil {
			return err
		}
	}
	return nil
}

func (k *Kanidm) UpdateOAuth2(name string, display, landing *string, redirects []string, pkce *bool) error {
	if _, err := k.OAuth2(name); err != nil {
		return err
	}
	p := "/v1/oauth2/" + esc(name) + "/_attr/"
	if display != nil {
		if err := k.do("PUT", p+"displayname", []string{*display}, nil); err != nil {
			return err
		}
	}
	if landing != nil {
		if err := k.do("PUT", p+"oauth2_rs_origin_landing", []string{*landing}, nil); err != nil {
			return err
		}
	}
	if redirects != nil {
		var err error
		if len(redirects) == 0 {
			if err = k.do("DELETE", p+"oauth2_rs_origin", nil, nil); errors.Is(err, ErrNotFound) {
				err = nil
			}
		} else {
			err = k.do("PUT", p+"oauth2_rs_origin", redirects, nil)
		}
		if err != nil {
			return err
		}
	}
	if pkce != nil {
		var err error
		if *pkce {
			if err = k.do("DELETE", p+"oauth2_allow_insecure_client_disable_pkce", nil, nil); errors.Is(err, ErrNotFound) {
				err = nil
			}
		} else {
			err = k.do("PUT", p+"oauth2_allow_insecure_client_disable_pkce", []string{"true"}, nil)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *Kanidm) SetScopeMap(name, group string, scopes []string) error {
	return k.do("POST", "/v1/oauth2/"+esc(name)+"/_scopemap/"+esc(group), scopes, nil)
}

func (k *Kanidm) DeleteScopeMap(name, group string) error {
	err := k.do("DELETE", "/v1/oauth2/"+esc(name)+"/_scopemap/"+esc(group), nil, nil)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

func (k *Kanidm) OAuth2Secret(name string, reset bool) (string, error) {
	if _, err := k.OAuth2(name); err != nil {
		return "", err
	}
	if reset {
		// an empty value makes Kanidm generate a new secret
		if err := k.do("PATCH", "/v1/oauth2/"+esc(name), map[string]any{"attrs": map[string][]string{"oauth2_rs_basic_secret": {}}}, nil); err != nil {
			return "", err
		}
	}
	var s string
	if err := k.do("GET", "/v1/oauth2/"+esc(name)+"/_basic_secret", nil, &s); err != nil {
		return "", err
	}
	return s, nil
}

func (k *Kanidm) SetShortName(name string, on bool) error {
	// PUT …/_attr/oauth2_prefer_short_username is a 405 in Kanidm 1.10: the entry's PATCH
	// (an empty list removes the attribute, as for the basic secret)
	v := []string{}
	if on {
		v = []string{"true"}
	}
	return k.do("PATCH", "/v1/oauth2/"+esc(name), map[string]any{"attrs": map[string][]string{"oauth2_prefer_short_username": v}}, nil)
}

func (k *Kanidm) DeleteOAuth2(name string) error {
	return k.do("DELETE", "/v1/oauth2/"+esc(name), nil, nil)
}

// ---- service accounts (LDAP device accounts)

func (k *Kanidm) ServiceAccounts() ([]ServiceAccount, error) {
	var es []entry
	if err := k.do("GET", "/v1/service_account", nil, &es); err != nil {
		return nil, err
	}
	out := []ServiceAccount{}
	for i := range es {
		e := &es[i]
		if builtinGroup(e) { // anonymous, admin, idm_admin and the like
			continue
		}
		sa := ServiceAccount{Name: e.one("name"), DisplayName: e.one("displayname"), UUID: e.one("uuid"), Groups: []string{}}
		for _, g := range e.Attrs["directmemberof"] {
			sa.Groups = append(sa.Groups, spnName(g))
		}
		sort.Strings(sa.Groups)
		var toks []json.RawMessage
		if err := k.do("GET", "/v1/service_account/"+esc(sa.Name)+"/_api_token", nil, &toks); err == nil {
			sa.Tokens = len(toks)
		}
		out = append(out, sa)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (k *Kanidm) CreateServiceAccount(name, display string, groups []string) error {
	attrs := map[string][]string{"name": {name}, "displayname": {display}, "entry_managed_by": {"idm_admin"}}
	if err := k.do("POST", "/v1/service_account", map[string]any{"attrs": attrs}, nil); err != nil {
		return err
	}
	for _, g := range groups {
		if err := k.do("POST", "/v1/group/"+esc(g)+"/_attr/member", []string{name}, nil); err != nil {
			k.do("DELETE", "/v1/service_account/"+esc(name), nil, nil) // not half made
			return fmt.Errorf("into %s: %v", g, err)
		}
	}
	return nil
}

func (k *Kanidm) DeleteServiceAccount(name string) error {
	return k.do("DELETE", "/v1/service_account/"+esc(name), nil, nil)
}

func (k *Kanidm) NewAPIToken(name, label string) (string, error) {
	var toks []struct {
		ID string `json:"token_id"`
	}
	if err := k.do("GET", "/v1/service_account/"+esc(name)+"/_api_token", nil, &toks); err != nil {
		return "", err
	}
	for _, t := range toks {
		if err := k.do("DELETE", "/v1/service_account/"+esc(name)+"/_api_token/"+esc(t.ID), nil, nil); err != nil {
			return "", fmt.Errorf("revoking the old token: %v", err)
		}
	}
	var tok string
	if err := k.do("POST", "/v1/service_account/"+esc(name)+"/_api_token",
		map[string]any{"label": label, "expiry": nil, "read_write": false}, &tok); err != nil {
		return "", err
	}
	if tok == "" {
		return "", errors.New("kanidm gave no token")
	}
	return tok, nil
}
