package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"keelauth/internal/engine"
	"keelauth/internal/sys"
)

// apiError is an answer other than 200: {"error": "…", "code": "…"} with its status code.
type apiError struct {
	Status int
	Msg    string
	Code   string
}

func (e *apiError) Error() string { return e.Msg }

func bad(format string, a ...any) error {
	return &apiError{http.StatusBadRequest, fmt.Sprintf(format, a...), ""}
}
func notFound(format string, a ...any) error {
	return &apiError{http.StatusNotFound, fmt.Sprintf(format, a...), ""}
}
func conflict(format string, a ...any) error {
	return &apiError{http.StatusConflict, fmt.Sprintf(format, a...), ""}
}
func coded(status int, code, format string, a ...any) error {
	return &apiError{status, fmt.Sprintf(format, a...), code}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	b, _ := json.Marshal(v)
	w.Write(append(b, '\n'))
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	var we *engine.WeakPasswordError
	switch {
	case errors.As(err, &ae):
		m := map[string]string{"error": ae.Msg}
		if ae.Code != "" {
			m["code"] = ae.Code
		}
		writeJSON(w, ae.Status, m)
	case errors.As(err, &we):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": we.Error(), "code": "weak_password"})
	case errors.Is(err, engine.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.Is(err, engine.ErrExists):
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	default:
		var ce *sys.CmdError
		if errors.As(err, &ce) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": ce.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
	}
}

func decode(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return bad("cannot read the request: %v", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return bad("the request has no JSON body")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return bad("bad JSON: %v", err)
	}
	return nil
}

// decodeOpt is decode for a body that may be empty.
func decodeOpt(r *http.Request, v any) error {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return bad("cannot read the request: %v", err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return bad("bad JSON: %v", err)
	}
	return nil
}

type handler func(r *http.Request) (any, error)

func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v, err := h(r)
		c := caller(r)
		if err != nil {
			if r.Method != http.MethodGet {
				s.Log.Printf("%s %s %s: %v", c.Name, r.Method, r.URL.Path, err)
			}
			writeErr(w, err)
			return
		}
		if r.Method != http.MethodGet {
			s.Log.Printf("%s %s %s: ok", c.Name, r.Method, r.URL.Path)
		}
		writeJSON(w, http.StatusOK, v)
	}
}

// ---- callers ----

// Caller is who sent a request.
type Caller struct {
	Name    string
	Admin   bool
	Kind    string // "local", "keel", "session", "token", "sync", ""
	Session *session
	TokenID string
}

type ctxKey struct{}

func caller(r *http.Request) *Caller {
	if c, ok := r.Context().Value(ctxKey{}).(*Caller); ok {
		return c
	}
	return &Caller{}
}

func withCaller(r *http.Request, c *Caller) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxKey{}, c))
}

func hashToken(t string) string { s := sha256.Sum256([]byte(t)); return hex.EncodeToString(s[:]) }

// identify finds the caller from the Authorization header or the session cookie.
func (s *Server) identify(r *http.Request) *Caller {
	if b, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
		k := s.linkKey()
		switch {
		case k != "" && subtle.ConstantTimeCompare([]byte(b), []byte(k)) == 1:
			return &Caller{Name: "keel", Admin: true, Kind: "keel"}
		case strings.HasPrefix(b, tokenPrefix):
			if id := s.useToken(b, false); id != "" {
				return &Caller{Name: "mcp:" + id, Admin: true, Kind: "token", TokenID: id}
			}
		case strings.HasPrefix(b, syncKeyPrefix):
			if id := s.useToken(b, true); id != "" {
				return &Caller{Name: "sync:" + id, Kind: "sync", TokenID: id}
			}
		}
		return &Caller{Kind: "bad"}
	}
	if ck, err := r.Cookie(sessionCookie); err == nil {
		if se := s.sessions.get(ck.Value, s.now()); se != nil {
			return &Caller{Name: se.Name, Admin: se.Admin, Kind: "session", Session: se}
		}
	}
	return &Caller{}
}

// ready: 503 code "starting" until Serve's first bring-up is over (Kanidm prepared: its groups,
// the bind account), so that nobody (keel making the first administrator, a login) gets an
// answer from a half-made engine.
func (s *Server) ready(h handler) handler {
	return func(r *http.Request) (any, error) {
		if s.Locked() {
			return nil, errLocked
		}
		if s.starting.Load() {
			return nil, coded(http.StatusServiceUnavailable, "starting", "keelAuth is starting (Kanidm is being prepared): try again in a few seconds")
		}
		return h(r)
	}
}

// Handler is everything: the web page, login, the API and MCP, each with its own check.
func (s *Server) Handler() http.Handler {
	s.hOnce.Do(func() { s.h = s.buildHandler() })
	return s.h
}

func (s *Server) buildHandler() http.Handler {
	m := http.NewServeMux()
	// no login needed
	m.HandleFunc("GET /login/state", s.wrap(s.getLoginState))
	m.HandleFunc("POST /login", s.wrap(s.ready(s.postLogin)))
	m.HandleFunc("POST /logout", s.postLogout)
	m.HandleFunc("GET /session", s.wrap(s.getSession))
	m.HandleFunc("POST /password", s.need(s.loggedIn, s.wrap(s.ready(s.postOwnPassword))))
	// a locked master key (masterkey.go): nobody can log in, so no login for this; tries are limited
	m.HandleFunc("POST /unlock", s.wrap(s.postUnlock))
	// the API (admins)
	a := func(pat string, h handler) {
		if pat != "GET /v1/status" && pat != "GET /v1/alerts" && pat != "GET /v1/settings" {
			h = s.ready(h)
		}
		m.HandleFunc(pat, s.need(s.admin, s.wrap(h)))
	}
	a("GET /v1/status", s.getStatus)
	a("GET /v1/users", s.getUsers)
	a("POST /v1/users", s.postUser)
	a("GET /v1/users/{name}", s.getUser)
	a("PATCH /v1/users/{name}", s.patchUser)
	a("POST /v1/users/{name}/password", s.postUserPassword)
	a("DELETE /v1/users/{name}", s.deleteUser)
	a("GET /v1/groups", s.getGroups)
	a("POST /v1/groups", s.postGroup)
	a("PATCH /v1/groups/{name}", s.patchGroup)
	a("POST /v1/groups/{name}/members", s.postMembers)
	a("DELETE /v1/groups/{name}", s.deleteGroup)
	a("GET /v1/oidc", s.getOIDC)
	a("POST /v1/oidc", s.postOIDC)
	a("GET /v1/oidc/{name}", s.getOIDCOne)
	a("PATCH /v1/oidc/{name}", s.patchOIDC)
	a("POST /v1/oidc/{name}/secret", s.postOIDCSecret)
	a("DELETE /v1/oidc/{name}", s.deleteOIDC)
	a("PUT /v1/oidc/{name}/roles", s.putOIDCRoles)
	a("GET /v1/radius", s.getRadius)
	a("PUT /v1/radius", s.putRadius)
	a("POST /v1/radius/clients", s.postRadiusClient)
	a("PATCH /v1/radius/clients/{name}", s.patchRadiusClient)
	a("DELETE /v1/radius/clients/{name}", s.deleteRadiusClient)
	a("GET /v1/ldap", s.getLDAP)
	a("POST /v1/ldap/bind", s.postLDAPBind)
	a("GET /v1/ldap/devices", s.getDevices)
	a("POST /v1/ldap/devices", s.postDevice)
	a("POST /v1/ldap/devices/{name}/password", s.postDevicePassword)
	a("DELETE /v1/ldap/devices/{name}", s.deleteDevice)
	a("GET /v1/ldap/examples", s.getLDAPExamples)
	a("GET /v1/certs", s.getCerts)
	a("POST /v1/certs/office", s.postOfficeCert)
	a("DELETE /v1/certs/office", s.deleteOfficeCert)
	m.HandleFunc("GET /v1/ca", s.need(s.admin, http.HandlerFunc(s.getCA)))
	m.HandleFunc("GET /v1/ca/mobileconfig", s.need(s.admin, http.HandlerFunc(s.getMobileconfig)))
	// the CA for everybody (no login): a phone or laptop of the office fetches it from
	// https://<keelAuth>/ca/… before it trusts anything (a CA certificate is public)
	m.HandleFunc("GET /ca/keelauth-ca.crt", s.getCA)
	m.HandleFunc("GET /ca/keelauth-ca.cer", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		q.Set("format", "der")
		r.URL.RawQuery = q.Encode()
		s.getCA(w, r)
	})
	m.HandleFunc("GET /ca/keelauth-ca.mobileconfig", s.getMobileconfig)
	a("GET /v1/backups", s.getBackups)
	a("POST /v1/backups", s.postBackup)
	a("POST /v1/backups/upload", s.postUpload)
	m.HandleFunc("GET /v1/backups/{name}", s.need(s.admin, http.HandlerFunc(s.getBackupFile)))
	a("POST /v1/backups/{name}/restore", s.postRestore)
	a("PUT /v1/recovery", s.putRecovery)
	a("GET /v1/alerts", s.getAlerts)
	a("GET /v1/settings", s.getSettings)
	a("PUT /v1/settings", s.putSettings)
	a("GET /v1/tokens", s.getTokens)
	a("POST /v1/tokens", s.postToken)
	a("DELETE /v1/tokens/{id}", s.deleteToken)
	a("GET /v1/sync/keys", s.getSyncKeys)
	a("POST /v1/sync/keys", s.postSyncKey)
	a("DELETE /v1/sync/keys/{id}", s.deleteSyncKey)
	m.HandleFunc("GET /v1/sync/accounts", s.need(s.syncer, s.wrap(s.ready(s.getSyncAccounts))))
	m.Handle("POST /mcp", s.need(s.mcpCaller, s.mcpHandler()))
	m.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, notFound("no such API: %s %s", r.Method, r.URL.Path))
	})
	// the web page
	m.Handle("/", s.static())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Context().Value(ctxKey{}).(*Caller); !ok {
			r = withCaller(r, s.identify(r))
		}
		r = r.WithContext(context.WithValue(r.Context(), rwKey{}, w))
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		m.ServeHTTP(w, r)
	})
}

// local is the handler for the Unix socket: root on the VM, an admin.
func (s *Server) local(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, withCaller(r, &Caller{Name: "root", Admin: true, Kind: "local"}))
	})
}

// internalOnly is the internal link's listener: only keel's key.
func (s *Server) internalOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := s.identify(r)
		if c.Kind != "keel" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "a valid key is required"})
			return
		}
		h.ServeHTTP(w, withCaller(r, c))
	})
}

// need runs h when ok(caller) is nil, else answers its error. Requests with a session cookie
// that change something need the session's CSRF token in X-Keelauth-CSRF.
func (s *Server) need(ok func(c *Caller) error, h http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c := caller(r)
		if err := ok(c); err != nil {
			writeErr(w, err)
			return
		}
		if c.Kind == "session" && r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Keelauth-CSRF")), []byte(c.Session.CSRF)) != 1 {
				writeErr(w, coded(http.StatusForbidden, "csrf", "missing or wrong X-Keelauth-CSRF header"))
				return
			}
		}
		h.ServeHTTP(w, r)
	}
}

func (s *Server) loggedIn(c *Caller) error {
	if c.Kind == "session" || c.Kind == "local" || c.Kind == "keel" {
		return nil
	}
	return coded(http.StatusUnauthorized, "login", "log in first")
}

func (s *Server) admin(c *Caller) error {
	switch {
	case c.Kind == "bad":
		return coded(http.StatusUnauthorized, "bad_token", "a valid key is required")
	case c.Kind == "" || c.Kind == "token" || c.Kind == "sync": // an MCP token works through /mcp (kind "mcp")
		if c.Kind == "" {
			return coded(http.StatusUnauthorized, "login", "log in first")
		}
		return coded(http.StatusForbidden, "scope", "this token is only for %s", map[string]string{"token": "POST /mcp", "sync": "GET /v1/sync/accounts"}[c.Kind])
	case !c.Admin:
		return coded(http.StatusForbidden, "not_admin", "only members of %s may manage keelAuth", AdminGroup)
	case c.Kind == "session" && s.mustChange(c.Name):
		return coded(http.StatusForbidden, "must_change", "change your password first (POST password)")
	}
	return nil
}

func (s *Server) mustChange(name string) bool {
	d := s.State().Users[name]
	return d != nil && d.MustChange
}

// syncer: a sync key, keel's key or root on the VM (never a web session or an MCP token: the
// answer carries NT hashes).
func (s *Server) syncer(c *Caller) error {
	switch c.Kind {
	case "sync", "keel", "local":
		return nil
	case "", "bad":
		return coded(http.StatusUnauthorized, "login", "a sync key is required")
	}
	return coded(http.StatusForbidden, "scope", "only a sync key may read the accounts with their NT hashes")
}

func (s *Server) mcpCaller(c *Caller) error {
	switch c.Kind {
	case "token", "keel", "local":
		return nil
	case "session":
		if c.Admin {
			return nil
		}
	}
	if c.Kind == "session" {
		return coded(http.StatusForbidden, "not_admin", "only members of %s may manage keelAuth", AdminGroup)
	}
	return coded(http.StatusUnauthorized, "bad_token", "an MCP token is required")
}
