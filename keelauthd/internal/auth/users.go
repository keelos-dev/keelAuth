package auth

import (
	"errors"
	"net/http"
	"net/mail"
	"slices"
	"sort"
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
	Password    string   `json:"password,omitempty"` // only when keelauthd made one
}

func (s *Server) userOut(u *engine.User) UserOut {
	o := UserOut{Name: u.Name, DisplayName: u.DisplayName, Mail: u.Mail, Enabled: u.Enabled, Groups: u.Groups, UID: u.UID,
		Admin: slices.Contains(u.Groups, AdminGroup)}
	if o.Groups == nil {
		o.Groups = []string{}
	}
	if d := s.State().Users[u.Name]; d != nil {
		o.HasNT, o.SetAt, o.MustChange = d.NT != "", d.SetAt, d.MustChange
	}
	return o
}

func (s *Server) getUsers(r *http.Request) (any, error) {
	us, err := s.Eng.Users()
	if err != nil {
		return nil, err
	}
	out := []UserOut{}
	for i := range us {
		if us[i].Name == BindAccount {
			continue
		}
		out = append(out, s.userOut(&us[i]))
	}
	return map[string]any{"users": out}, nil
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
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	switch {
	case !ValidName(req.Name):
		return nil, bad("user name %q: lower-case letters, digits, - and _, a letter first, at most 32", req.Name)
	case reserved(req.Name):
		return nil, conflict("the name %q is reserved", req.Name)
	case !validMail(req.Mail):
		return nil, bad("mail %q is not an address", req.Mail)
	}
	if err := s.checkGroups(req.Groups); err != nil {
		return nil, err
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
	if len(req.Groups) > 0 {
		if err := s.setUserGroups(req.Name, req.Groups); err != nil {
			return nil, err
		}
		s.radiusLater()
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
		DisplayName *string   `json:"display_name"`
		Mail        *string   `json:"mail"`
		Groups      *[]string `json:"groups"`
		Enabled     *bool     `json:"enabled"`
		MustChange  *bool     `json:"must_change"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Mail != nil && !validMail(*req.Mail) {
		return nil, bad("mail %q is not an address", *req.Mail)
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
	s.radiusLater()
	return map[string]any{}, nil
}
