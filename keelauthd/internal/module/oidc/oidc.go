package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"html"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/module/limit"
)

// Directory is what the provider reads: keelauthd's view of the account store.
type Directory interface {
	// Origin is where browsers reach this provider: https://auth.office.lan:8443 (no path).
	Origin() string
	Domain() string
	// Brand: the company's name for the pages ("" = keelAuth) and its logo's URL ("" = none).
	Brand() (name, logo string)
	Clients() []engine.OAuth2
	Client(id string) (*engine.OAuth2, bool)
	CheckSecret(id, secret string) bool
	CheckPassword(name, password string) bool
	Person(name string) (Person, bool)
	// Allowed: the person may use this client (keelauthd's access rights).
	Allowed(name, client string) bool
}

// Person is a user as the provider sees them.
type Person struct {
	Name        string
	DisplayName string
	Mail        string
	UUID        string
	Groups      []string // flattened
}

const (
	sessionCookie = "keelauth_sso"
	sessionTTL    = 12 * time.Hour
	codeTTL       = 2 * time.Minute
	accessTTL     = time.Hour
	refreshTTL    = 30 * 24 * time.Hour
	maxPending    = 10000
)

// Server is the provider: an http.Handler keelauthd serves on the origin's port.
type Server struct {
	Dir Directory
	Log *log.Logger
	Now func() time.Time // tests

	keys *keyStore
	lim  limit.Limiter
	mu   sync.Mutex
	sess map[string]*session
	code map[string]*grant
	acc  map[string]*token // access tokens
	ref  map[string]*token // refresh tokens
}

type session struct {
	user    string
	created time.Time
	seen    time.Time
}

// grant is an authorization code waiting for the token endpoint.
type grant struct {
	client, user, redirect, nonce, challenge, method string
	scopes                                           []string
	auth                                             time.Time // when the user logged in
	exp                                              time.Time
}

type token struct {
	client, user, nonce string
	scopes              []string
	auth, exp           time.Time
}

// New makes a provider; dir holds its key file ("" = keys in memory).
func New(dir Directory, keyDir string, lg *log.Logger) (*Server, error) {
	ks, err := newKeyStore(keyDir)
	if err != nil {
		return nil, err
	}
	return &Server{Dir: dir, Log: lg, keys: ks, sess: map[string]*session{}, code: map[string]*grant{}, acc: map[string]*token{}, ref: map[string]*token{}}, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log.Printf("oidc: "+format, a...)
	}
}

// ClientDeleted forgets a client's keys.
func (s *Server) ClientDeleted(id string) { s.keys.drop(id) }

// Issuer is a client's issuer.
func (s *Server) Issuer(client string) string {
	return s.Dir.Origin() + "/oauth2/openid/" + url.PathEscape(client)
}

// ServeHTTP routes the provider's paths.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/oauth2/openid/"):
		rest := strings.TrimPrefix(p, "/oauth2/openid/")
		client, sub, _ := strings.Cut(rest, "/")
		client, _ = url.PathUnescape(client)
		switch sub {
		case ".well-known/openid-configuration":
			s.discovery(w, r, client)
		case "userinfo":
			s.userinfo(w, r, client)
		case "public_key.jwk":
			s.jwks(w, r, client)
		default:
			http.NotFound(w, r)
		}
	case p == "/ui/oauth2":
		s.authorize(w, r)
	case p == "/oauth2/token":
		s.token(w, r)
	case p == "/oauth2/token/introspect":
		s.introspect(w, r)
	case p == "/ui/login":
		s.login(w, r)
	case p == "/ui/logout":
		s.logout(w, r)
	case p == "/ui/apps" || p == "/ui" || p == "/ui/" || p == "/":
		s.apps(w, r)
	case p == "/ui/profile":
		http.Redirect(w, r, "/ui/apps", http.StatusFound)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func oauthErr(w http.ResponseWriter, code int, err, desc string) {
	writeJSON(w, code, map[string]string{"error": err, "error_description": desc})
}

// ---- discovery, keys ----

func (s *Server) discovery(w http.ResponseWriter, r *http.Request, client string) {
	c, ok := s.Dir.Client(client)
	if !ok {
		http.NotFound(w, r)
		return
	}
	o := s.Dir.Origin()
	iss := s.Issuer(client)
	alg := "ES256"
	if c.RS256 {
		alg = "RS256"
	}
	scopes := map[string]bool{"openid": true, "profile": true, "email": true, "groups": true}
	for _, ss := range c.ScopeMaps {
		for _, sc := range ss {
			scopes[sc] = true
		}
	}
	var list []string
	for sc := range scopes {
		list = append(list, sc)
	}
	sort.Strings(list)
	writeJSON(w, 200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                o + "/ui/oauth2",
		"token_endpoint":                        o + "/oauth2/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"jwks_uri":                              iss + "/public_key.jwk",
		"introspection_endpoint":                o + "/oauth2/token/introspect",
		"end_session_endpoint":                  o + "/ui/logout",
		"scopes_supported":                      list,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{alg},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "preferred_username", "name", "email", "email_verified", "groups"},
	})
}

func (s *Server) signerFor(c *engine.OAuth2) (*signer, error) {
	alg := "ES256"
	if c.RS256 {
		alg = "RS256"
	}
	return s.keys.get(c.Name, alg)
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request, client string) {
	c, ok := s.Dir.Client(client)
	if !ok {
		http.NotFound(w, r)
		return
	}
	sg, err := s.signerFor(c)
	if err != nil {
		oauthErr(w, 500, "server_error", err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"keys": []any{sg.jwk()}})
}

// ---- sessions ----

func (s *Server) sessionUser(r *http.Request) (string, time.Time) {
	ck, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	se := s.sess[ck.Value]
	now := s.now()
	if se == nil || now.Sub(se.created) > sessionTTL {
		delete(s.sess, ck.Value)
		return "", time.Time{}
	}
	se.seen = now
	return se.user, se.created
}

func (s *Server) newSession(w http.ResponseWriter, user string) {
	id := random(32)
	s.mu.Lock()
	if len(s.sess) > maxPending {
		s.sess = map[string]*session{}
	}
	s.sess[id] = &session{user: user, created: s.now(), seen: s.now()}
	s.mu.Unlock()
	// host-only (no Domain): the cookie belongs to whatever address the browser used
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: id, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL / time.Second)})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(sessionCookie); err == nil {
		s.mu.Lock()
		delete(s.sess, ck.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	if to := r.URL.Query().Get("post_logout_redirect_uri"); to != "" && s.knownRedirect(to) {
		http.Redirect(w, r, to, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/ui/login", http.StatusFound)
}

func (s *Server) knownRedirect(u string) bool {
	for _, c := range s.Dir.Clients() {
		for _, r := range c.RedirectURLs {
			if r == u {
				return true
			}
		}
		if c.LandingURL == u {
			return true
		}
	}
	return false
}

// ---- login page ----

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// safeReturn: where to go after the login: a path of this provider only.
func safeReturn(v string) string {
	if strings.HasPrefix(v, "/ui/") && !strings.HasPrefix(v, "//") {
		return v
	}
	return "/ui/apps"
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ret := safeReturn(r.FormValue("return"))
	if r.Method == http.MethodGet {
		if u, _ := s.sessionUser(r); u != "" {
			http.Redirect(w, r, ret, http.StatusFound)
			return
		}
		s.page(w, r, loginPage{ret: ret})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	name := strings.ToLower(strings.TrimSpace(r.FormValue("username")))
	if i := strings.Index(name, "@"); i > 0 { // alice@domain
		name = name[:i]
	}
	pw := r.FormValue("password")
	ip := clientIP(r)
	if wait := s.lim.Blocked(ip, name); wait > 0 {
		s.page(w, r, loginPage{ret: ret, name: name, err: "too many failed logins: try again in " + wait.Round(time.Second).String()})
		return
	}
	if name == "" || pw == "" || !s.Dir.CheckPassword(name, pw) {
		s.lim.Failed(ip, name)
		s.logf("login %s from %s: refused", name, ip)
		s.page(w, r, loginPage{ret: ret, name: name, err: "wrong user name or password"})
		return
	}
	s.lim.OK(ip, name)
	s.newSession(w, name)
	http.Redirect(w, r, ret, http.StatusSeeOther)
}

// ---- authorization ----

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	c, ok := s.Dir.Client(q.Get("client_id"))
	if !ok {
		s.errorPage(w, r, "unknown application (client_id)")
		return
	}
	redirect := q.Get("redirect_uri")
	if !contains(c.RedirectURLs, redirect) {
		s.errorPage(w, r, "the application's redirect address is not registered: "+redirect)
		return
	}
	back := func(err, desc string) {
		u, _ := url.Parse(redirect)
		v := u.Query()
		v.Set("error", err)
		v.Set("error_description", desc)
		if st := q.Get("state"); st != "" {
			v.Set("state", st)
		}
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		back("unsupported_response_type", "only code")
		return
	}
	asked := strings.Fields(q.Get("scope"))
	if !contains(asked, "openid") {
		back("invalid_scope", "openid is needed")
		return
	}
	challenge, method := q.Get("code_challenge"), q.Get("code_challenge_method")
	if method == "" && challenge != "" {
		method = "plain"
	}
	if c.PKCE && (challenge == "" || method != "S256") {
		back("invalid_request", "PKCE with S256 is required for this application")
		return
	}
	user, auth := s.sessionUser(r)
	if user == "" {
		http.Redirect(w, r, "/ui/login?return="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
		return
	}
	p, ok := s.Dir.Person(user)
	if !ok {
		s.logout(w, r)
		return
	}
	granted, allowed := scopesFor(c, p, asked)
	if !allowed || !s.Dir.Allowed(p.Name, c.Name) {
		s.logf("authorize %s for %s: not in a group of the application", p.Name, c.Name)
		s.errorPage(w, r, "you have no access to "+displayName(c)+": ask the administrator to put you in its group")
		return
	}
	code := random(32)
	s.mu.Lock()
	s.sweep()
	s.code[code] = &grant{client: c.Name, user: p.Name, redirect: redirect, nonce: q.Get("nonce"), challenge: challenge, method: method, scopes: granted, auth: auth, exp: s.now().Add(codeTTL)}
	s.mu.Unlock()
	u, _ := url.Parse(redirect)
	v := u.Query()
	v.Set("code", code)
	if st := q.Get("state"); st != "" {
		v.Set("state", st)
	}
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func displayName(c *engine.OAuth2) string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return c.Name
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// scopesFor: the scopes the person gets of the asked ones: those the client maps to a group
// the person is in (idm_all_persons = everyone); openid always. Not in any mapped group:
// no access.
func scopesFor(c *engine.OAuth2, p Person, asked []string) ([]string, bool) {
	mapped := map[string]bool{}
	allowed := false
	for g, scopes := range c.ScopeMaps {
		if g == engine.AllPersons || contains(p.Groups, g) {
			allowed = true
			for _, sc := range scopes {
				mapped[sc] = true
			}
		}
	}
	if !allowed {
		return nil, false
	}
	out := []string{}
	for _, sc := range asked {
		if sc == "openid" || mapped[sc] {
			out = append(out, sc)
		}
	}
	return out, true
}

// sweep drops expired codes and tokens (under mu).
func (s *Server) sweep() {
	now := s.now()
	for k, g := range s.code {
		if now.After(g.exp) {
			delete(s.code, k)
		}
	}
	for k, t := range s.acc {
		if now.After(t.exp) {
			delete(s.acc, k)
		}
	}
	for k, t := range s.ref {
		if now.After(t.exp) {
			delete(s.ref, k)
		}
	}
	for k, se := range s.sess {
		if now.Sub(se.created) > sessionTTL {
			delete(s.sess, k)
		}
	}
}

// ---- token ----

// clientAuth: the client's id and secret from Basic auth or the form.
func clientAuth(r *http.Request) (id, secret string) {
	if u, p, ok := r.BasicAuth(); ok {
		u, _ = url.QueryUnescape(u)
		p, _ = url.QueryUnescape(p)
		return u, p
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, 405, "invalid_request", "POST")
		return
	}
	r.ParseForm()
	id, secret := clientAuth(r)
	if wait := s.lim.Blocked(clientIP(r), "client:"+id); wait > 0 {
		oauthErr(w, 429, "invalid_client", "too many failed attempts: try again later")
		return
	}
	c, ok := s.Dir.Client(id)
	if !ok || !s.Dir.CheckSecret(id, secret) {
		s.lim.Failed(clientIP(r), "client:"+id)
		w.Header().Set("WWW-Authenticate", `Basic realm="keelAuth"`)
		oauthErr(w, 401, "invalid_client", "unknown application or wrong secret")
		return
	}
	s.lim.OK("client:" + id)
	switch r.PostFormValue("grant_type") {
	case "authorization_code":
		s.mu.Lock()
		g := s.code[r.PostFormValue("code")]
		delete(s.code, r.PostFormValue("code")) // one use
		s.mu.Unlock()
		if g == nil || s.now().After(g.exp) || g.client != c.Name {
			oauthErr(w, 400, "invalid_grant", "unknown or expired code")
			return
		}
		if g.redirect != r.PostFormValue("redirect_uri") {
			oauthErr(w, 400, "invalid_grant", "redirect_uri differs")
			return
		}
		if g.challenge != "" {
			ver := r.PostFormValue("code_verifier")
			var want string
			if g.method == "S256" {
				sum := sha256.Sum256([]byte(ver))
				want = b64u(sum[:])
			} else {
				want = ver
			}
			if ver == "" || subtle.ConstantTimeCompare([]byte(want), []byte(g.challenge)) != 1 {
				oauthErr(w, 400, "invalid_grant", "PKCE verifier does not match")
				return
			}
		}
		s.issue(w, c, g.user, g.nonce, g.scopes, g.auth, true)
	case "refresh_token":
		s.mu.Lock()
		t := s.ref[r.PostFormValue("refresh_token")]
		if t != nil {
			delete(s.ref, r.PostFormValue("refresh_token")) // rotated
		}
		s.mu.Unlock()
		if t == nil || s.now().After(t.exp) || t.client != c.Name {
			oauthErr(w, 400, "invalid_grant", "unknown or expired refresh token")
			return
		}
		if _, ok := s.Dir.Person(t.user); !ok { // gone or disabled meanwhile
			oauthErr(w, 400, "invalid_grant", "the account is gone")
			return
		}
		s.issue(w, c, t.user, "", t.scopes, t.auth, true)
	default:
		oauthErr(w, 400, "unsupported_grant_type", "authorization_code or refresh_token")
	}
}

// issue answers the token endpoint: access token, ID token, refresh token.
func (s *Server) issue(w http.ResponseWriter, c *engine.OAuth2, user, nonce string, scopes []string, auth time.Time, withRefresh bool) {
	p, ok := s.Dir.Person(user)
	if !ok || !s.Dir.Allowed(user, c.Name) {
		oauthErr(w, 400, "invalid_grant", "the account is gone or no longer allowed")
		return
	}
	now := s.now()
	sg, err := s.signerFor(c)
	if err != nil {
		oauthErr(w, 500, "server_error", err.Error())
		return
	}
	claims := s.claims(c, p, scopes)
	claims["iss"] = s.Issuer(c.Name)
	claims["aud"] = c.Name
	claims["azp"] = c.Name
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(accessTTL).Unix()
	claims["auth_time"] = auth.Unix()
	if nonce != "" {
		claims["nonce"] = nonce
	}
	idToken, err := sg.sign(claims)
	if err != nil {
		oauthErr(w, 500, "server_error", err.Error())
		return
	}
	acc := random(32)
	s.mu.Lock()
	s.acc[acc] = &token{client: c.Name, user: user, nonce: nonce, scopes: scopes, auth: auth, exp: now.Add(accessTTL)}
	out := map[string]any{"access_token": acc, "token_type": "Bearer", "expires_in": int(accessTTL / time.Second), "id_token": idToken, "scope": strings.Join(scopes, " ")}
	if withRefresh {
		rt := random(32)
		s.ref[rt] = &token{client: c.Name, user: user, scopes: scopes, auth: auth, exp: now.Add(refreshTTL)}
		out["refresh_token"] = rt
	}
	s.mu.Unlock()
	writeJSON(w, 200, out)
}

// claims are the person's claims for the scopes (sub always; profile, email, groups by scope).
func (s *Server) claims(c *engine.OAuth2, p Person, scopes []string) map[string]any {
	out := map[string]any{"sub": p.UUID}
	if c.ShortName {
		out["preferred_username"] = p.Name
	} else {
		out["preferred_username"] = p.Name + "@" + s.Dir.Domain()
	}
	for _, sc := range scopes {
		switch sc {
		case "profile":
			name := p.DisplayName
			if name == "" {
				name = p.Name
			}
			out["name"] = name
		case "email":
			if p.Mail != "" {
				out["email"] = p.Mail
				out["email_verified"] = true
			}
		case "groups":
			gs := append([]string(nil), p.Groups...)
			sort.Strings(gs)
			out["groups"] = gs
		}
	}
	return out
}

// bearer is the access token of a request.
func (s *Server) bearer(r *http.Request) *token {
	h := r.Header.Get("Authorization")
	v, ok := strings.CutPrefix(h, "Bearer ")
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.acc[strings.TrimSpace(v)]
	if t == nil || s.now().After(t.exp) {
		return nil
	}
	return t
}

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request, client string) {
	t := s.bearer(r)
	if t == nil || t.client != client {
		w.Header().Set("WWW-Authenticate", `Bearer realm="keelAuth"`)
		oauthErr(w, 401, "invalid_token", "")
		return
	}
	c, ok := s.Dir.Client(client)
	p, ok2 := s.Dir.Person(t.user)
	if !ok || !ok2 || !s.Dir.Allowed(t.user, client) {
		oauthErr(w, 401, "invalid_token", "")
		return
	}
	writeJSON(w, 200, s.claims(c, p, t.scopes))
}

// introspect (RFC 7662): a client asks about an access token (a mail server checking what a
// webmail got).
func (s *Server) introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		oauthErr(w, 405, "invalid_request", "POST")
		return
	}
	r.ParseForm()
	id, secret := clientAuth(r)
	if _, ok := s.Dir.Client(id); !ok || !s.Dir.CheckSecret(id, secret) {
		s.lim.Failed(clientIP(r), "client:"+id)
		oauthErr(w, 401, "invalid_client", "")
		return
	}
	s.mu.Lock()
	t := s.acc[r.PostFormValue("token")]
	s.mu.Unlock()
	if t == nil || s.now().After(t.exp) {
		writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	p, ok := s.Dir.Person(t.user)
	if !ok {
		writeJSON(w, 200, map[string]any{"active": false})
		return
	}
	writeJSON(w, 200, map[string]any{"active": true, "client_id": t.client, "username": p.Name, "sub": p.UUID, "scope": strings.Join(t.scopes, " "),
		"exp": t.exp.Unix(), "iat": t.auth.Unix(), "token_type": "Bearer"})
}

// ---- pages ----

type loginPage struct{ ret, name, err string }

func (s *Server) apps(w http.ResponseWriter, r *http.Request) {
	user, _ := s.sessionUser(r)
	if user == "" {
		http.Redirect(w, r, "/ui/login?return=%2Fui%2Fapps", http.StatusFound)
		return
	}
	p, ok := s.Dir.Person(user)
	if !ok {
		s.logout(w, r)
		return
	}
	var items []string
	for _, c := range s.Dir.Clients() {
		if _, allowed := scopesFor(&c, p, []string{"openid"}); !allowed || c.LandingURL == "" || !s.Dir.Allowed(p.Name, c.Name) {
			continue
		}
		items = append(items, `<a class="app" href="`+html.EscapeString(c.LandingURL)+`"><span class="mark">`+html.EscapeString(strings.ToUpper(c.Name[:1]))+`</span><span>`+html.EscapeString(displayName(&c))+`</span></a>`)
	}
	body := `<h1>Applications</h1><p class="muted">` + html.EscapeString(p.Name) + `</p>`
	if len(items) == 0 {
		body += `<p class="muted">No application yet.</p>`
	} else {
		body += `<div class="apps">` + strings.Join(items, "") + `</div>`
	}
	body += `<p class="muted small"><a href="/ui/logout">Sign out</a></p>`
	s.render(w, "Applications", body)
}

func (s *Server) errorPage(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, "Error", `<h1>Cannot continue</h1><p class="error">`+html.EscapeString(msg)+`</p><p class="muted small"><a href="/ui/apps">Applications</a></p>`)
}

func (s *Server) page(w http.ResponseWriter, r *http.Request, lp loginPage) {
	errHTML := ""
	if lp.err != "" {
		errHTML = `<p class="error">` + html.EscapeString(lp.err) + `</p>`
	}
	brand, _ := s.Dir.Brand()
	if brand == "" {
		brand = "keelAuth"
	}
	body := `<h1>Sign in to ` + html.EscapeString(brand) + `</h1>` + errHTML +
		`<form method="post" action="/ui/login"><input type="hidden" name="return" value="` + html.EscapeString(lp.ret) + `">` +
		`<input type="text" name="username" autocomplete="username" placeholder="User name" value="` + html.EscapeString(lp.name) + `" required autofocus spellcheck="false" autocapitalize="off">` +
		`<input type="password" name="password" autocomplete="current-password" placeholder="Password" required>` +
		`<button type="submit">Sign in</button></form>`
	s.render(w, "Sign in", body)
}

// render is the shell every page shares: one small style, the brand, no scripts (keel's
// policy for the pages it passes through allows none of ours).
func (s *Server) render(w http.ResponseWriter, title, body string) {
	brand, logo := s.Dir.Brand()
	if brand == "" {
		brand = "keelAuth"
	}
	logoHTML := ""
	if logo != "" {
		logoHTML = `<img class="logo" src="` + html.EscapeString(logo) + `" alt="">`
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'self'")
	w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` + html.EscapeString(title+" · "+brand) + `</title><style>` + css + `</style></head><body><main>` +
		`<div class="brand">` + logoHTML + `<span>` + html.EscapeString(brand) + `</span></div>` + body + `</main></body></html>`))
}

const css = `
:root{color-scheme:light dark;font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans CJK SC","Noto Sans CJK JP",sans-serif;font-size:15px}
body{margin:0;background:#f4f5f7;color:#1c1e21}@media(prefers-color-scheme:dark){body{background:#15171a;color:#e6e6e6}}
main{max-width:420px;margin:8vh auto;padding:28px 24px;background:#fff;border:1px solid #d9dce1}
@media(prefers-color-scheme:dark){main{background:#1e2126;border-color:#30343a}}
.brand{display:flex;align-items:center;gap:10px;font-weight:600;font-size:17px;margin-bottom:18px;color:#0b3d91}@media(prefers-color-scheme:dark){.brand{color:#8ab4f8}}
.logo{height:28px}h1{font-size:20px;margin:0 0 14px}p{margin:8px 0}.muted{color:#6b7280}.small{font-size:13px}.error{color:#b42318}
input{display:block;width:100%;box-sizing:border-box;margin:8px 0;padding:9px 10px;border:1px solid #c6cad1;font:inherit;background:transparent;color:inherit}
button{width:100%;margin-top:10px;padding:10px;border:0;background:#1a56db;color:#fff;font:inherit;font-weight:600;cursor:pointer}
.apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:12px;margin:14px 0}
.app{display:flex;flex-direction:column;align-items:center;gap:8px;padding:14px 8px;border:1px solid #d9dce1;color:inherit;text-decoration:none;text-align:center}
.app:hover{border-color:#1a56db}.mark{width:44px;height:44px;display:grid;place-items:center;background:#1a56db;color:#fff;font-weight:700;font-size:20px}
a{color:#1a56db}
`
