package auth

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"keelauth/internal/secret"
)

// The web page's login (docs/02 section 3.2): a user of keelAuth with their password (checked
// by the engine). Members of keelauth-admins manage keelAuth; everybody else can only change
// their own password. Sessions are kept in memory and in <data>/sessions (sealed with the master
// key, 0600), so a restart of keelauthd (an upgrade, a crash) logs nobody out. The file is
// written on every login, logout and drop, and at most once a minute for "last seen".

const (
	sessionFile   = "sessions"
	sessionCookie = "keelauth_session"
	sessionIdle   = 2 * time.Hour
	sessionMax    = 12 * time.Hour
	failLimit     = 5
	failWait      = 5 * time.Minute
)

type session struct {
	ID      string
	CSRF    string
	Name    string
	Admin   bool
	Created time.Time
	Seen    time.Time
}

type sessions struct {
	mu    sync.Mutex
	m     map[string]*session
	fails map[string][]time.Time // by user name
	// save keeps the sessions (nil: memory only); saved is when it last did
	save  func([]session)
	saved time.Time
}

func newSessions() *sessions {
	return &sessions{m: map[string]*session{}, fails: map[string][]time.Time{}}
}

// persist hands a copy of the sessions to save; called with mu held.
func (ss *sessions) persist(now time.Time) {
	if ss.save == nil {
		return
	}
	list := make([]session, 0, len(ss.m))
	for _, se := range ss.m {
		list = append(list, *se)
	}
	ss.saved = now
	ss.save(list)
}

// restore puts saved sessions back, the stale ones left out.
func (ss *sessions) restore(list []session, now time.Time) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for i := range list {
		se := list[i]
		if se.ID == "" || now.Sub(se.Seen) > sessionIdle || now.Sub(se.Created) > sessionMax {
			continue
		}
		ss.m[se.ID] = &se
	}
}

// loadSessions reads <data>/sessions (a missing or unreadable file: nobody is logged in).
func (s *Server) loadSessions() {
	if s.box == nil {
		return
	}
	b, err := s.Sys.ReadFile(filepath.Join(s.Data, sessionFile))
	if err != nil {
		return
	}
	plain, err := s.box.Open(strings.TrimSpace(string(b)))
	if err != nil {
		s.Log.Printf("sessions: %v (everybody logs in again)", err)
		return
	}
	var list []session
	if err := json.Unmarshal([]byte(plain), &list); err != nil {
		s.Log.Printf("sessions: %v (everybody logs in again)", err)
		return
	}
	s.sessions.restore(list, s.now())
}

// saveSessions writes <data>/sessions.
func (s *Server) saveSessions(list []session) {
	if s.Locked() {
		return
	}
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	if err := s.Sys.WriteFile(filepath.Join(s.Data, sessionFile), []byte(s.box.Seal(string(b))+"\n"), 0o600); err != nil {
		s.Log.Printf("sessions: %v", err)
	}
}

func (ss *sessions) get(id string, now time.Time) *session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	se := ss.m[id]
	if se == nil {
		return nil
	}
	if now.Sub(se.Seen) > sessionIdle || now.Sub(se.Created) > sessionMax {
		delete(ss.m, id)
		ss.persist(now)
		return nil
	}
	se.Seen = now
	if now.Sub(ss.saved) > time.Minute {
		ss.persist(now)
	}
	c := *se
	return &c
}

func (ss *sessions) add(name string, admin bool, now time.Time) *session {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for id, se := range ss.m { // drop the stale ones
		if now.Sub(se.Seen) > sessionIdle || now.Sub(se.Created) > sessionMax {
			delete(ss.m, id)
		}
	}
	se := &session{ID: secret.Random(32), CSRF: secret.Random(16), Name: name, Admin: admin, Created: now, Seen: now}
	ss.m[se.ID] = se
	ss.persist(now)
	c := *se
	return &c
}

func (ss *sessions) drop(id string) {
	ss.mu.Lock()
	delete(ss.m, id)
	ss.persist(time.Now())
	ss.mu.Unlock()
}

// clear ends every session (after a restore).
func (ss *sessions) clear() {
	ss.mu.Lock()
	ss.m = map[string]*session{}
	ss.persist(time.Now())
	ss.mu.Unlock()
}

// dropUser ends a user's sessions (deleted, disabled, removed from the admins).
func (ss *sessions) dropUser(name string) {
	ss.mu.Lock()
	for id, se := range ss.m {
		if se.Name == name {
			delete(ss.m, id)
		}
	}
	ss.persist(time.Now())
	ss.mu.Unlock()
}

// blocked reports whether name has failed too often lately; fail records a failure.
func (ss *sessions) blocked(name string, now time.Time) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	f := slices.DeleteFunc(ss.fails[name], func(t time.Time) bool { return now.Sub(t) > failWait })
	ss.fails[name] = f
	return len(f) >= failLimit
}

func (ss *sessions) fail(name string, now time.Time) {
	ss.mu.Lock()
	ss.fails[name] = append(ss.fails[name], now)
	ss.mu.Unlock()
}

func (ss *sessions) ok(name string) {
	ss.mu.Lock()
	delete(ss.fails, name)
	ss.mu.Unlock()
}

// SessionInfo is the answer of /login and /session.
type SessionInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Admin       bool   `json:"admin"`
	CSRF        string `json:"csrf"`
	MustChange  bool   `json:"must_change"`
	ViaKeel     bool   `json:"via_keel,omitempty"`
	Timezone    string `json:"timezone"` // the zone the page shows times in (timezone.go)
}

func (s *Server) getLoginState(r *http.Request) (any, error) {
	st := s.State()
	admins := false
	if g, err := s.Eng.Group(AdminGroup); err == nil && len(g.Members) > 0 {
		admins = true
	}
	return map[string]any{"hostname": s.hostname(), "version": s.versionString(), "domain": st.Domain, "admins": admins,
		"timezone": s.zoneFor(r), "locked": s.Locked(), "managed_by_keel": s.managed()}, nil
}

func (s *Server) info(name string, admin bool, csrf string) SessionInfo {
	in := SessionInfo{Name: name, Admin: admin, CSRF: csrf}
	if u, err := s.Eng.User(name); err == nil {
		in.DisplayName = u.DisplayName
	}
	if d := s.State().Users[name]; d != nil {
		in.MustChange = d.MustChange
	}
	return in
}

func (s *Server) getSession(r *http.Request) (any, error) {
	c := caller(r)
	switch c.Kind {
	case "keel", "local":
		return SessionInfo{Name: c.Name, Admin: true, ViaKeel: c.Kind == "keel", Timezone: s.zoneFor(r)}, nil
	case "session":
		in := s.info(c.Name, c.Admin, c.Session.CSRF)
		in.Timezone = s.zoneFor(r)
		return in, nil
	}
	return nil, coded(http.StatusUnauthorized, "login", "not logged in")
}

// isAdmin reports whether name is in keelauth-admins.
func (s *Server) isAdmin(name string) bool {
	g, err := s.Eng.Group(AdminGroup)
	return err == nil && slices.Contains(g.Members, name)
}

func (s *Server) postLogin(r *http.Request) (any, error) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	now := s.now()
	if !ValidName(name) || name == BindAccount || req.Password == "" {
		return nil, coded(http.StatusUnauthorized, "bad_login", "wrong user name or password")
	}
	if s.sessions.blocked(name, now) {
		return nil, coded(http.StatusTooManyRequests, "too_many", "too many failed logins: wait a few minutes")
	}
	u, err := s.Eng.User(name)
	if err != nil {
		s.sessions.fail(name, now)
		return nil, coded(http.StatusUnauthorized, "bad_login", "wrong user name or password")
	}
	if !u.Enabled {
		return nil, coded(http.StatusUnauthorized, "disabled", "this account is disabled")
	}
	ok, err := s.Eng.CheckPassword(name, req.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.sessions.fail(name, now)
		s.Log.Printf("login %s from %s: wrong password", name, r.RemoteAddr)
		return nil, coded(http.StatusUnauthorized, "bad_login", "wrong user name or password")
	}
	s.sessions.ok(name)
	admin := slices.Contains(u.Groups, AdminGroup)
	se := s.sessions.add(name, admin, now)
	if w, ok := r.Context().Value(rwKey{}).(http.ResponseWriter); ok {
		setCookie(w, r, se.ID, int(sessionMax.Seconds()))
	}
	s.Log.Printf("login %s from %s (admin %v)", name, r.RemoteAddr, admin)
	in := s.info(name, admin, se.CSRF)
	in.Timezone = s.zoneFor(r)
	return in, nil
}

// rwKey carries the ResponseWriter to handlers that set cookies (login).
type rwKey struct{}

func setCookie(w http.ResponseWriter, r *http.Request, v string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: v, MaxAge: maxAge, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.drop(ck.Value)
	}
	setCookie(w, r, "", -1)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// postOwnPassword: a logged-in user changes their own password (old and new).
func (s *Server) postOwnPassword(r *http.Request) (any, error) {
	c := caller(r)
	if c.Kind != "session" {
		return nil, bad("only a logged-in user changes their own password here; use /v1/users/NAME/password")
	}
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	ok, err := s.Eng.CheckPassword(c.Name, req.Old)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, coded(http.StatusBadRequest, "bad_password", "the current password is wrong")
	}
	if req.New == req.Old {
		return nil, coded(http.StatusBadRequest, "weak_password", "the new password is the same as the old one")
	}
	if err := s.setPassword(c.Name, req.New, false); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}
