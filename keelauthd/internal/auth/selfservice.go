package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/module/totp"
)

// An employee's own business (their password, their authenticator app) done for them by a
// trusted front end with a sync key that has self_service: the in-home client through the
// gateway, say (docs/02 §9.5, docs/05 §1.6). Every call proves the person again, as verify
// does and on the same counter of wrong tries; somebody without an authenticator gets in on
// the password alone, since setting one up is what they came for.

// initialPasswordMax: an initial password (must_change, from an administrator) older than this
// no longer opens verify and these calls: the administrator sets it again.
const initialPasswordMax = 14 * 24 * time.Hour

// selfServiceWhere: "page" (keelAuth's own page, the default) or "app".
func (s *Server) selfServiceWhere() string {
	if s.State().SelfServiceWhere == "app" {
		return "app"
	}
	return "page"
}

// elsewhere refuses a non-administrator's own business on the page when it is done in another app.
func (s *Server) elsewhere(c *Caller) error {
	if c != nil && c.Kind == "session" && !c.Admin && s.selfServiceWhere() == "app" {
		return coded(http.StatusForbidden, "elsewhere", "change your password and authenticator in the app your company gave you")
	}
	return nil
}

// initialExpired: the password is an initial one and too old to be used from outside.
func (s *Server) initialExpired(name string) bool {
	d := s.State().Users[name]
	if d == nil || !d.MustChange || d.SetAt == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, d.SetAt)
	return err == nil && s.now().Sub(t) > initialPasswordMax
}

// selfNeeds: what the person still has to do before verify lets them in through the key.
func (s *Server) selfNeeds(name string, key *Token) []string {
	out := []string{}
	if d := s.State().Users[name]; d != nil && d.MustChange {
		out = append(out, "password")
	}
	if key != nil && key.RequireTOTP && !s.totpNeeded(name) {
		out = append(out, "totp")
	}
	return out
}

type selfReq struct {
	Name        string `json:"name"`
	Password    string `json:"password"`
	Code        string `json:"code"`
	NewPassword string `json:"new_password"`
	NewCode     string `json:"new_code"`
	// Features: the person's own values of self_edit feature modules (features.go)
	Features map[string]json.RawMessage `json:"features"`
}

// selfProve: the key may do this, and the person is who they say (password, and the code
// when they have an authenticator).
func (s *Server) selfProve(r *http.Request) (*selfReq, *engine.User, *Token, error) {
	var req selfReq
	if err := decode(r, &req); err != nil {
		return nil, nil, nil, err
	}
	c := caller(r)
	key := s.syncKeyOf(c)
	if key == nil || !key.SelfService {
		return nil, nil, nil, coded(http.StatusForbidden, "not_self_service", "this key may not do an employee's own business (a sync key with self_service)")
	}
	name := strings.ToLower(strings.TrimSpace(req.Name))
	req.Name = name
	now := s.now()
	badLogin := coded(http.StatusUnauthorized, "bad_login", "wrong user name or password")
	if !ValidUserName(name) || name == BindAccount || req.Password == "" {
		return nil, nil, nil, badLogin
	}
	if s.sessions.blocked(name, now) {
		return nil, nil, nil, coded(http.StatusTooManyRequests, "too_many", "too many failed logins: wait a few minutes")
	}
	u, err := s.Eng.User(name)
	if err != nil {
		s.sessions.fail(name, now)
		return nil, nil, nil, badLogin
	}
	ok, err := s.Eng.CheckPassword(name, req.Password)
	if err != nil {
		return nil, nil, nil, err
	}
	if !ok {
		s.sessions.fail(name, now)
		s.Log.Printf("self %s for sync key %s: wrong password", name, key.Name)
		return nil, nil, nil, badLogin
	}
	if !u.Enabled {
		return nil, nil, nil, coded(http.StatusUnauthorized, "disabled", "this account is disabled")
	}
	if !s.allowed(name, consumerOfSync(c)) {
		return nil, nil, nil, coded(http.StatusForbidden, "not_allowed", "this account may not use this service")
	}
	if s.totpNeeded(name) {
		if strings.TrimSpace(req.Code) == "" {
			return nil, nil, nil, coded(http.StatusUnauthorized, "totp_required", "enter the code from your authenticator app")
		}
		if !s.totpCheck(name, req.Code) {
			s.sessions.fail(name, now)
			s.Log.Printf("self %s for sync key %s: wrong code", name, key.Name)
			return nil, nil, nil, coded(http.StatusUnauthorized, "bad_code", "the code is wrong")
		}
	}
	if s.initialExpired(name) {
		return nil, nil, nil, coded(http.StatusForbidden, "password_expired", "this initial password has expired: ask the administrator for a new one")
	}
	s.sessions.ok(name)
	return &req, u, key, nil
}

func (s *Server) selfStatus(name string, key *Token) (any, error) {
	u, err := s.Eng.User(name)
	if err != nil {
		return nil, err
	}
	minLen, strength := s.State().PasswordPolicy()
	out := map[string]any{"name": u.Name, "display_name": u.DisplayName, "groups": u.Groups,
		"totp": s.totpNeeded(name), "totp_set_at": s.totpSetAt(name), "must_change": false, "password_set_at": "",
		"needs": s.selfNeeds(name, key), "password_rules": map[string]any{"min_length": minLen, "strength": strength}}
	if key != nil && len(key.Features) > 0 {
		out["features"] = s.featureValues(name, key.Features)
	}
	if u.Groups == nil {
		out["groups"] = []string{}
	}
	if d := s.State().Users[name]; d != nil {
		out["must_change"], out["password_set_at"] = d.MustChange, d.SetAt
	}
	return out, nil
}

func (s *Server) postSelf(r *http.Request) (any, error) {
	req, _, key, err := s.selfProve(r)
	if err != nil {
		return nil, err
	}
	return s.selfStatus(req.Name, key)
}

func (s *Server) postSelfPassword(r *http.Request) (any, error) {
	req, _, key, err := s.selfProve(r)
	if err != nil {
		return nil, err
	}
	if req.NewPassword == "" {
		return nil, bad("new_password: the new password")
	}
	if req.NewPassword == req.Password {
		return nil, coded(http.StatusBadRequest, "weak_password", "the new password is the same as the old one")
	}
	if err := s.setPassword(req.Name, req.NewPassword, false); err != nil {
		return nil, err
	}
	s.sessions.dropUser(req.Name)
	s.Log.Printf("self %s for sync key %s: password changed", req.Name, key.Name)
	return s.selfStatus(req.Name, key)
}

func (s *Server) postSelfTOTP(r *http.Request) (any, error) {
	req, _, key, err := s.selfProve(r)
	if err != nil {
		return nil, err
	}
	if !s.moduleOn("totp") {
		return nil, coded(http.StatusConflict, "totp_off", "the totp module is off: ask the administrator")
	}
	secret, u := s.totpStart(req.Name)
	s.Log.Printf("self %s for sync key %s: setting up an authenticator", req.Name, key.Name)
	return map[string]any{"secret": secret, "url": u, "expires_s": int(totpEnrolTTL.Seconds())}, nil
}

func (s *Server) postSelfTOTPConfirm(r *http.Request) (any, error) {
	req, _, key, err := s.selfProve(r)
	if err != nil {
		return nil, err
	}
	totpMu.Lock()
	p, ok := totpEnrols[req.Name]
	totpMu.Unlock()
	if !ok || s.now().After(p.expires) {
		return nil, coded(http.StatusBadRequest, "no_enrolment", "no authenticator being set up (or it expired): start again")
	}
	if ok, _ := totp.Verify(p.secret, req.NewCode, s.now()); !ok {
		return nil, coded(http.StatusBadRequest, "bad_new_code", "the code from the new authenticator is wrong: check the phone's clock and try the next one")
	}
	if err := s.totpSave(req.Name, p.secret); err != nil {
		return nil, err
	}
	s.Log.Printf("self %s for sync key %s: authenticator set up", req.Name, key.Name)
	return s.selfStatus(req.Name, key)
}
