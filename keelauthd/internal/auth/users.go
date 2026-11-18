package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/secret"
)

// UserOut is a user in the API.
type UserOut struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Mail        string   `json:"mail"`
	Enabled     bool     `json:"enabled"`
	Groups      []string `json:"groups"`
	UID         int      `json:"uid"`
	HasNT       bool     `json:"has_nt"`
	SetAt       string   `json:"password_set_at"`
	MustChange  bool     `json:"must_change"`
	Admin       bool     `json:"admin"`
	MailDomains []string `json:"mail_domains"`       // ticked mail domains (maildomains.go)
	Addresses   []string `json:"addresses"`          // the mailboxes those give
	Password    string   `json:"password,omitempty"` // only when keelauthd made one
	// TOTP: an authenticator app is set up and asked for (the module is on); TOTPSetAt: when.
	// A sync key with require_totp lets nobody without one in (docs/02 §9.2).
	TOTP      bool   `json:"totp"`
	TOTPSetAt string `json:"totp_set_at"`
	// Features: the values of the feature modules that are on (features.go, docs/02 §10).
	Features map[string]any `json:"features,omitempty"`
	// Services: every service the account has now, and how (docs/05 §1.10).
	Services []UserService `json:"services"`
}

// UserService is one service an account may use. Via: the group that gives it (the account
// is in it, directly or through a group in it), "*" = the service is open to every
// account, "tick" = a mail domain ticked for the account.
type UserService struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Name string `json:"name"`
	Via  string `json:"via"`
}

// userView is what userOut needs of the whole (the memberships, the services), gathered
// once for a list of accounts.
type userView struct {
	ac   accessChecker
	cons []Consumer
}

func (s *Server) userView() userView {
	v := userView{ac: s.accessChecker()}
	st := v.ac.st
	v.cons = []Consumer{{ID: AccessSMB, Kind: "smb", Name: "keelNAS"}}
	if s.moduleOn("ldap") {
		v.cons = append(v.cons, Consumer{ID: AccessLDAP, Kind: "ldap", Name: "LDAP"})
	}
	if s.moduleOn("radius") {
		v.cons = append(v.cons, Consumer{ID: AccessWiFi, Kind: "wifi", Name: "Wi-Fi"})
	}
	if cs, err := s.Eng.OAuth2s(); err == nil && s.moduleOn("oidc") {
		for _, c := range cs {
			name := c.DisplayName
			if name == "" {
				name = c.Name
			}
			v.cons = append(v.cons, Consumer{ID: accessOIDC + c.Name, Kind: "oidc", Name: name})
		}
	}
	for _, k := range st.SyncKeys {
		v.cons = append(v.cons, Consumer{ID: accessSync + k.ID, Kind: "sync", Name: k.Name})
	}
	if s.legacyEngine() { // Kanidm serves these to everybody itself (docs/02 §9.4)
		for i := range v.cons {
			v.cons[i].Unlimited = v.cons[i].Kind == "ldap" || v.cons[i].Kind == "oidc"
		}
	}
	return v
}

func (v userView) services(name string) []UserService {
	out := []UserService{}
	for _, c := range v.cons {
		via := v.ac.via(name, c.ID)
		if c.Unlimited {
			via = everyAccount
		}
		if via != "" {
			out = append(out, UserService{ID: c.ID, Kind: c.Kind, Name: c.Name, Via: via})
		}
	}
	return out
}

func (s *Server) userOut(u *engine.User) UserOut { return s.userOutIn(s.userView(), u) }

func (s *Server) userOutIn(v userView, u *engine.User) UserOut {
	o := UserOut{Name: u.Name, DisplayName: u.DisplayName, Mail: u.Mail, Enabled: u.Enabled, Groups: u.Groups, UID: u.UID,
		Admin: slices.Contains(u.Groups, AdminGroup)}
	if o.Groups == nil {
		o.Groups = []string{}
	}
	o.MailDomains, o.Addresses = []string{}, v.ac.addresses(u.Name)
	o.Services = v.services(u.Name)
	o.TOTP, o.TOTPSetAt = s.totpNeeded(u.Name), s.totpSetAt(u.Name)
	if fs := s.enabledFeatures(); len(fs) > 0 {
		o.Features = s.featureValues(u.Name, fs)
	}
	if d := s.State().Users[u.Name]; d != nil {
		o.HasNT, o.SetAt, o.MustChange = d.NT != "", d.SetAt, d.MustChange
		if d.MailDomains != nil {
			o.MailDomains = d.MailDomains
		}
	}
	return o
}

func (s *Server) getUsers(r *http.Request) (any, error) {
	us, err := s.Eng.Users()
	if err != nil {
		return nil, err
	}
	keep, err := s.userFilter(r.URL.Query())
	if err != nil {
		return nil, err
	}
	out := []UserOut{}
	view := s.userView()
	for i := range us {
		if us[i].Name == BindAccount {
			continue
		}
		if o := s.userOutIn(view, &us[i]); keep(&o) {
			out = append(out, o)
		}
	}
	return map[string]any{"users": out}, nil
}

// userFilter: GET /v1/users?q=…&<field>=… (docs/02 §10.4). q: the text is somewhere in the
// name, the display name, the mail addresses or a value of a feature module (case ignored).
// <field>: a field of a one-row feature module that is on has exactly this value
// (employeeNumber=11011, employeeType=contract; an empty value = accounts without one).
func (s *Server) userFilter(q url.Values) (func(*UserOut) bool, error) {
	type exact struct{ module, field, want string }
	var exacts []exact
	text := ""
	for k, vs := range q {
		if k == "q" {
			text = strings.ToLower(strings.TrimSpace(vs[0]))
			continue
		}
		found := false
		for _, f := range featureDefs {
			if f.Rows || !s.moduleOn(f.Name) {
				continue
			}
			for _, fd := range f.Fields {
				if fd.Name == k {
					exacts, found = append(exacts, exact{f.Name, k, vs[0]}), true
				}
			}
		}
		if !found {
			return nil, bad("no filter %q: q, or a field of a feature module that is on", k)
		}
	}
	val := func(o *UserOut, module, field string) string {
		if m, ok := o.Features[module].(map[string]any); ok && m[field] != nil {
			return fmt.Sprint(m[field])
		}
		return ""
	}
	return func(o *UserOut) bool {
		for _, e := range exacts {
			if !strings.EqualFold(val(o, e.module, e.field), e.want) {
				return false
			}
		}
		if text == "" {
			return true
		}
		hay := []string{o.Name, o.DisplayName, o.Mail}
		hay = append(hay, o.Addresses...)
		for _, v := range o.Features {
			if m, ok := v.(map[string]any); ok {
				for _, x := range m {
					hay = append(hay, fmt.Sprint(x))
				}
			}
		}
		return slices.ContainsFunc(hay, func(h string) bool { return strings.Contains(strings.ToLower(h), text) })
	}, nil
}

// lookupUser is the engine's user; the bind account does not exist for the API.
func (s *Server) lookupUser(name string) (*engine.User, error) {
	if name == BindAccount {
		return nil, notFound("no user %q", name)
	}
	u, err := s.Eng.User(name)
	if errors.Is(err, engine.ErrNotFound) {
		return nil, notFound("no user %q", name)
	}
	return u, err
}

func (s *Server) getUser(r *http.Request) (any, error) {
	u, err := s.lookupUser(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	return s.userOut(u), nil
}

func validMail(m string) bool {
	if m == "" {
		return true
	}
	a, err := mail.ParseAddress(m)
	return err == nil && a.Address == m
}

// setPassword sets a password in the engine and keeps its NT hash (docs/02 section 1).
func (s *Server) setPassword(name, pw string, mustChange bool) error {
	if pw == "" {
		return bad("the password is empty")
	}
	if err := s.Eng.SetPassword(name, pw); err != nil {
		return err
	}
	nt := s.box.Seal(secret.NTHash(pw))
	err := s.update(func(st *State) error {
		d := st.user(name)
		d.NT, d.SetAt, d.MustChange = nt, s.now().Format(time.RFC3339), mustChange
		return nil
	}, true)
	if err != nil {
		return err
	}
	s.radiusLater()
	return nil
}

// checkGroups: every group exists (in the engine).
func (s *Server) checkGroups(gs []string) error {
	for _, g := range gs {
		if _, err := s.Eng.Group(g); err != nil {
			if errors.Is(err, engine.ErrNotFound) {
				return bad("no group %q", g)
			}
			return err
		}
	}
	return nil
}

// setUserGroups makes name a member of exactly groups (keelAuth's groups).
func (s *Server) setUserGroups(name string, groups []string) error {
	all, err := s.Eng.Groups()
	if err != nil {
		return err
	}
	for _, g := range all {
		in, want := slices.Contains(g.Members, name), slices.Contains(groups, g.Name)
		if in == want {
			continue
		}
		m := slices.DeleteFunc(slices.Clone(g.Members), func(x string) bool { return x == name })
		if want {
			m = append(m, name)
		}
		m = append(m, g.MemberGroups...) // nested groups stay
		sort.Strings(m)
		if err := s.Eng.SetMembers(g.Name, m); err != nil {
			return err
		}
	}
	if !slices.Contains(groups, AdminGroup) {
		s.sessions.dropUser(name) // an admin no more: log in again
	}
	return nil
}

func (s *Server) postUser(r *http.Request) (any, error) {
	var req struct {
		Name        string   `json:"name"`
		DisplayName string   `json:"display_name"`
		Mail        string   `json:"mail"`
		Password    string   `json:"password"`
		MustChange  *bool    `json:"must_change"`
		Groups      []string `json:"groups"`
		// Access: the account's own list of services, before services had groups
		// (access.go): taken and not kept, so an older caller is not refused.
		Access      *[]string                  `json:"access"`
		MailDomains []string                   `json:"mail_domains"`
		Features    map[string]json.RawMessage `json:"features"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.checkMailDomains(req.MailDomains); err != nil {
		return nil, err
	}
	switch {
	case !ValidUserName(req.Name):
		return nil, bad("user name %q: lower-case letters, digits, -, _ and dots (not first, not last, not two in a row), a letter first, at most 32", req.Name)
	case reserved(req.Name):
		return nil, conflict("the name %q is reserved", req.Name)
	case !validMail(req.Mail):
		return nil, bad("mail %q is not an address", req.Mail)
	}
	if err := s.checkGroups(req.Groups); err != nil {
		return nil, err
	}
	for n, raw := range req.Features { // checked before the account is made: no half-made accounts
		f := findFeature(n)
		if f == nil || !s.moduleOn(n) {
			return nil, bad("no feature module %q that is on", n)
		}
		if _, err := s.normalizeFeature(f, req.Name, raw); err != nil {
			return nil, bad("%v", err)
		}
	}
	display := req.DisplayName
	if display == "" {
		display = req.Name
	}
	made := ""
	pw := req.Password
	if pw == "" {
		pw = secret.Password()
		made = pw
	}
	must := made != ""
	if req.MustChange != nil {
		must = *req.MustChange
	}
	if _, err := s.Eng.CreateUser(req.Name, display, req.Mail); err != nil {
		if errors.Is(err, engine.ErrExists) {
			return nil, conflict("the name %q is taken (a user or a group)", req.Name)
		}
		return nil, err
	}
	// a refused password undoes the user: nobody wants a half-made account
	if err := s.setPassword(req.Name, pw, must); err != nil {
		s.Eng.DeleteUser(req.Name)
		s.update(func(st *State) error { delete(st.Users, req.Name); return nil }, false)
		return nil, err
	}
	if len(req.MailDomains) > 0 {
		if err := s.update(func(st *State) error {
			st.user(req.Name).MailDomains = cleanList(req.MailDomains)
			return nil
		}, true); err != nil {
			return nil, err
		}
	}
	if len(req.Groups) > 0 {
		if err := s.setUserGroups(req.Name, req.Groups); err != nil {
			return nil, err
		}
		s.radiusLater()
	}
	if err := s.setFeatures(req.Name, req.Features, nil); err != nil {
		return nil, err
	}
	u, err := s.lookupUser(req.Name)
	if err != nil {
		return nil, err
	}
	o := s.userOut(u)
	o.Password = made
	return o, nil
}

func (s *Server) patchUser(r *http.Request) (any, error) {
	name := r.PathValue("name")
	u, err := s.lookupUser(name)
	if err != nil {
		return nil, err
	}
	var req struct {
		DisplayName *string                    `json:"display_name"`
		Mail        *string                    `json:"mail"`
		Groups      *[]string                  `json:"groups"`
		Enabled     *bool                      `json:"enabled"`
		MustChange  *bool                      `json:"must_change"`
		Access      *[]string                  `json:"access"` // taken and not kept (postUser)
		MailDomains *[]string                  `json:"mail_domains"`
		Features    map[string]json.RawMessage `json:"features"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	// the feature modules' values first: a refused one changes nothing else either
	if err := s.setFeatures(u.Name, req.Features, nil); err != nil {
		return nil, err
	}
	if req.Mail != nil && !validMail(*req.Mail) {
		return nil, bad("mail %q is not an address", *req.Mail)
	}
	if req.MailDomains != nil {
		if err := s.checkMailDomains(*req.MailDomains); err != nil {
			return nil, err
		}
		if err := s.update(func(st *State) error {
			st.user(u.Name).MailDomains = cleanList(*req.MailDomains)
			return nil
		}, true); err != nil {
			return nil, err
		}
	}
	if req.Groups != nil {
		if err := s.checkGroups(*req.Groups); err != nil {
			return nil, err
		}
		if err := s.lastAdmin(name, !slices.Contains(*req.Groups, AdminGroup)); err != nil {
			return nil, err
		}
	}
	if req.Enabled != nil && !*req.Enabled {
		if err := s.lastAdmin(name, true); err != nil {
			return nil, err
		}
	}
	changed := false
	if req.DisplayName != nil || req.Mail != nil {
		if err := s.Eng.UpdateUser(name, req.DisplayName, req.Mail); err != nil {
			return nil, err
		}
		changed = req.DisplayName != nil // the keelNAS sync carries the display name
	}
	if req.Groups != nil {
		if err := s.setUserGroups(name, *req.Groups); err != nil {
			return nil, err
		}
		changed = true
	}
	if req.Enabled != nil && *req.Enabled != u.Enabled {
		if err := s.Eng.SetEnabled(name, *req.Enabled); err != nil {
			return nil, err
		}
		if !*req.Enabled {
			s.sessions.dropUser(name)
		}
		changed = true
	}
	if req.MustChange != nil {
		if err := s.update(func(st *State) error { st.user(name).MustChange = *req.MustChange; return nil }, true); err != nil {
			return nil, err
		}
	}
	if changed {
		s.bump()
		s.radiusLater()
	}
	if u, err = s.lookupUser(name); err != nil {
		return nil, err
	}
	return s.userOut(u), nil
}

// lastAdmin refuses to take away the last enabled admin (nobody could log in to manage
// keelAuth any more, except through keel or the console).
func (s *Server) lastAdmin(name string, losing bool) error {
	if !losing {
		return nil
	}
	g, err := s.Eng.Group(AdminGroup)
	if err != nil || !slices.Contains(g.Members, name) {
		return nil
	}
	n := 0
	for _, m := range g.Members {
		if u, err := s.Eng.User(m); err == nil && u.Enabled {
			n++
		}
	}
	if n <= 1 {
		return conflict("%s is the last administrator: make another one first", name)
	}
	return nil
}

func (s *Server) postUserPassword(r *http.Request) (any, error) {
	name := r.PathValue("name")
	if _, err := s.lookupUser(name); err != nil {
		return nil, err
	}
	var req struct {
		Password   string `json:"password"`
		MustChange *bool  `json:"must_change"`
	}
	if err := decodeOpt(r, &req); err != nil {
		return nil, err
	}
	pw, made := req.Password, ""
	if pw == "" {
		pw = secret.Password()
		made = pw
	}
	must := true
	if req.MustChange != nil {
		must = *req.MustChange
	}
	if err := s.setPassword(name, pw, must); err != nil {
		return nil, err
	}
	s.dropPhones(name, "password reset by "+caller(r).Name)
	return map[string]any{"password": made, "must_change": must}, nil
}

func (s *Server) deleteUser(r *http.Request) (any, error) {
	name := r.PathValue("name")
	if _, err := s.lookupUser(name); err != nil {
		return nil, err
	}
	if err := s.lastAdmin(name, true); err != nil {
		return nil, err
	}
	if err := s.Eng.DeleteUser(name); err != nil {
		return nil, err
	}
	s.sessions.dropUser(name)
	if err := s.update(func(st *State) error { delete(st.Users, name); return nil }, true); err != nil {
		return nil, err
	}
	s.dropPhones(name, "account deleted")
	s.radiusLater()
	return map[string]any{}, nil
}
