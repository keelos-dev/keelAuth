package auth

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"keelauth/internal/module/totp"
	"keelauth/internal/secret"
)

// totpmod.go: the totp module (internal/module/totp): a second factor for the pages that can
// ask for one (keelAuth's own login, the oidc module's login page) when the user set one up
// (Settings → Phones and codes, or the password page). Protocols that cannot ask (LDAP,
// RADIUS, SMB, IMAP) are not touched. A phone login (phone module) needs no code: the phone
// is the stronger factor. The secret is sealed with the master key in the state.

const totpEnrolTTL = 10 * time.Minute

type totpPending struct {
	secret  string
	expires time.Time
}

var (
	totpMu      sync.Mutex
	totpEnrols  = map[string]totpPending{} // by user
	totpLast    = map[string]int64{}       // the last step a user's code was accepted at (no replay)
	totpOIDCTok = map[string]totpPending{} // oidc login page: password passed, code pending (secret = user)
)

// totpSet: the user has a code set up.
func (s *Server) totpSet(name string) bool {
	d := s.State().Users[name]
	return d != nil && d.TOTP != ""
}

// totpNeeded: the login must ask for a code.
func (s *Server) totpNeeded(name string) bool { return s.moduleOn("totp") && s.totpSet(name) }

// totpCheck verifies a code for the user (once per time step).
func (s *Server) totpCheck(name, code string) bool {
	d := s.State().Users[name]
	if d == nil || d.TOTP == "" {
		return false
	}
	secret, err := s.box.Open(d.TOTP)
	if err != nil {
		s.Log.Printf("totp %s: %v", name, err)
		return false
	}
	ok, step := totp.Verify(secret, code, s.now())
	if !ok {
		return false
	}
	totpMu.Lock()
	defer totpMu.Unlock()
	if totpLast[name] >= step {
		return false
	}
	totpLast[name] = step
	return true
}

// ---- the page ----

func (s *Server) getTOTP(r *http.Request) (any, error) {
	user, err := s.phoneUser(r, r.URL.Query().Get("user"))
	if err != nil {
		return nil, err
	}
	out := map[string]any{"enabled": s.moduleOn("totp"), "set": s.totpSet(user), "user": user}
	if d := s.State().Users[user]; d != nil && d.TOTPSetAt != "" {
		out["set_at"] = d.TOTPSetAt
	}
	return out, nil
}

// postTOTPEnroll starts the own code: the secret, the otpauth URL and its QR code; confirmed
// with the first code (postTOTPConfirm).
func (s *Server) postTOTPEnroll(r *http.Request) (any, error) {
	if !s.moduleOn("totp") {
		return nil, notFound("the totp module is off")
	}
	c := caller(r)
	if c.Kind != "session" {
		return nil, bad("only a logged-in user sets up their own code")
	}
	secret := totp.NewSecret()
	totpMu.Lock()
	totpEnrols[c.Name] = totpPending{secret, s.now().Add(totpEnrolTTL)}
	totpMu.Unlock()
	issuer, _ := oidcDir{s}.Brand()
	if issuer == "" {
		issuer = "keelAuth"
	}
	u := totp.URL(issuer, c.Name, secret)
	return map[string]any{"secret": secret, "url": u, "qr": qrData(u), "expires_s": int(totpEnrolTTL.Seconds())}, nil
}

func (s *Server) postTOTPConfirm(r *http.Request) (any, error) {
	c := caller(r)
	var req struct {
		Code string `json:"code"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	totpMu.Lock()
	p, ok := totpEnrols[c.Name]
	totpMu.Unlock()
	if !ok || s.now().After(p.expires) {
		return nil, bad("no code being set up (or it expired): start again")
	}
	if ok, _ := totp.Verify(p.secret, req.Code, s.now()); !ok {
		return nil, coded(http.StatusBadRequest, "bad_code", "the code is wrong: check the phone's clock and try the next one")
	}
	sealed := s.box.Seal(p.secret)
	if err := s.update(func(st *State) error {
		d := st.Users[c.Name]
		if d == nil {
			d = &UserData{}
			st.Users[c.Name] = d
		}
		d.TOTP, d.TOTPSetAt = sealed, s.now().UTC().Format(time.RFC3339)
		return nil
	}, false); err != nil {
		return nil, err
	}
	totpMu.Lock()
	delete(totpEnrols, c.Name)
	totpMu.Unlock()
	s.Log.Printf("totp: %s set up a code", c.Name)
	return map[string]any{"ok": true}, nil
}

// deleteTOTP removes the own code, or anybody's for an administrator (?user=: the phone
// is lost).
func (s *Server) deleteTOTP(r *http.Request) (any, error) {
	user, err := s.phoneUser(r, r.URL.Query().Get("user"))
	if err != nil {
		return nil, err
	}
	if err := s.update(func(st *State) error {
		if d := st.Users[user]; d != nil {
			d.TOTP, d.TOTPSetAt = "", ""
		}
		return nil
	}, false); err != nil {
		return nil, err
	}
	s.Log.Printf("totp: code of %s removed by %s", user, caller(r).Name)
	return map[string]any{"ok": true}, nil
}

// ---- the oidc module's login page (oidc.SecondFactor) ----

// SecondFactor: after the password, does the page have to ask for a code? It gets a token
// for the second step.
func (d oidcDir) SecondFactor(name string) (token string, needed bool) {
	if !d.s.totpNeeded(name) {
		return "", false
	}
	tok := secret.Random(24)
	totpMu.Lock()
	for k, v := range totpOIDCTok {
		if d.s.now().After(v.expires) {
			delete(totpOIDCTok, k)
		}
	}
	totpOIDCTok[tok] = totpPending{name, d.s.now().Add(3 * time.Minute)}
	totpMu.Unlock()
	return tok, true
}

// CheckSecondFactor: the token's user when the code is right ("" otherwise; the token is
// used up either way after three tries by the limiter upstream).
func (d oidcDir) CheckSecondFactor(token, code string) (name string, ok bool) {
	totpMu.Lock()
	p, found := totpOIDCTok[token]
	totpMu.Unlock()
	if !found || d.s.now().After(p.expires) {
		return "", false
	}
	if !d.s.totpCheck(p.secret, strings.TrimSpace(code)) {
		return p.secret, false
	}
	totpMu.Lock()
	delete(totpOIDCTok, token)
	totpMu.Unlock()
	return p.secret, true
}
