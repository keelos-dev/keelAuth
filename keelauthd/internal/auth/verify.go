package auth

import (
	"net/http"
	"strings"
)

// POST /v1/sync/verify (docs/02 section 9): a service that lets people in by itself, and has
// no web page of keelAuth's to send them to, asks here whether a name, a password and the
// authenticator app's code are right: a gateway that people log in to from outside the
// office. It calls with its sync key; the answer says yes only for an account its group
// lets in. The service never holds a password: it hands on what was typed, once.
//
// LDAP cannot do this: a bind has no place for the second factor, and a gateway reachable
// from the Internet should not be let in on a password alone. A key made with require_totp
// passes nobody without an authenticator app (the module off: nobody at all).
//
// What is told apart, for the service to say something useful to its user: a wrong name or
// password (bad_login, the two never told apart), the code missing (totp_required) or wrong
// (bad_code), no authenticator app though the key wants one (totp_not_set), an account that
// is right and not in the service's group (not_allowed) or disabled (disabled): the last
// three only after the password was right, so a stranger learns nothing from them. Wrong
// tries count as the page's do (five, then a wait that doubles), on the same counter.

type verifyOut struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Groups      []string `json:"groups"`
	// TOTP: a code was asked and was right.
	TOTP bool `json:"totp"`
	// TOTPSetAt: as in the sync (when the authenticator was set up, "" without one).
	TOTPSetAt string `json:"totp_set_at"`
	// MustChange: the administrator wants the password changed at the next login; the
	// service decides whether it lets such an account in.
	MustChange bool   `json:"must_change"`
	SetAt      string `json:"password_set_at"`
}

func (s *Server) postSyncVerify(r *http.Request) (any, error) {
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	c := caller(r)
	who := "keel"
	key := s.syncKeyOf(c)
	if key != nil {
		who = "sync key " + key.Name
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	now := s.now()
	badLogin := coded(http.StatusUnauthorized, "bad_login", "wrong user name or password")
	if !ValidName(name) || name == BindAccount || req.Password == "" {
		return nil, badLogin
	}
	if s.sessions.blocked(name, now) {
		return nil, coded(http.StatusTooManyRequests, "too_many", "too many failed logins: wait a few minutes")
	}
	u, err := s.Eng.User(name)
	if err != nil {
		s.sessions.fail(name, now)
		return nil, badLogin
	}
	ok, err := s.Eng.CheckPassword(name, req.Password)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.sessions.fail(name, now)
		s.Log.Printf("verify %s for %s: wrong password", name, who)
		return nil, badLogin
	}
	if !u.Enabled {
		return nil, coded(http.StatusUnauthorized, "disabled", "this account is disabled")
	}
	if consumer := consumerOfSync(c); c.Kind == "sync" && !s.allowed(name, consumer) {
		s.Log.Printf("verify %s for %s: not in its group", name, who)
		return nil, coded(http.StatusForbidden, "not_allowed", "this account may not use this service")
	}
	asked := s.totpNeeded(name)
	self := key != nil && key.SelfService // its front end can send the person to finish setting up (selfservice.go)
	if !asked && key != nil && key.RequireTOTP && !self {
		s.Log.Printf("verify %s for %s: no authenticator app", name, who)
		return nil, coded(http.StatusForbidden, "totp_not_set", "set up an authenticator app on keelAuth's page first")
	}
	if asked {
		if strings.TrimSpace(req.Code) == "" {
			return nil, coded(http.StatusUnauthorized, "totp_required", "enter the code from your authenticator app")
		}
		if !s.totpCheck(name, req.Code) {
			s.sessions.fail(name, now)
			s.Log.Printf("verify %s for %s: wrong code", name, who)
			return nil, coded(http.StatusUnauthorized, "bad_code", "the code is wrong")
		}
	}
	if s.initialExpired(name) {
		s.Log.Printf("verify %s for %s: initial password expired", name, who)
		return nil, coded(http.StatusForbidden, "password_expired", "this initial password has expired: ask the administrator for a new one")
	}
	if self && len(s.selfNeeds(name, key)) > 0 {
		s.Log.Printf("verify %s for %s: setting up not finished (%s)", name, who, strings.Join(s.selfNeeds(name, key), ", "))
		return nil, coded(http.StatusForbidden, "setup_needed", "the password or the authenticator app is still to be set up (POST /v1/sync/self says which)")
	}
	s.sessions.ok(name)
	s.Log.Printf("verify %s for %s: ok", name, who)
	out := verifyOut{Name: u.Name, DisplayName: u.DisplayName, Groups: u.Groups, TOTP: asked, TOTPSetAt: s.totpSetAt(u.Name)}
	if out.Groups == nil {
		out.Groups = []string{}
	}
	if d := s.State().Users[name]; d != nil {
		out.MustChange, out.SetAt = d.MustChange, d.SetAt
	}
	return out, nil
}
