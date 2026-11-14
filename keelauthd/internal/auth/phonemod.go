package auth

import (
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"time"

	"keelauth/internal/module/phone"
	"keelauth/internal/module/qr"
)

// phonemod.go: the phone module in keelauthd (internal/module/phone, docs/04): the devices
// live in the state, the pending enrolments and challenges in memory. The phone's own calls
// (/phone/enroll, /phone/approve) are on the web listener and on the oidc module's; the
// login pages (keelAuth's own and the oidc module's) get a challenge and poll it.

// phoneStore keeps the devices in the state.
type phoneStore struct{ s *Server }

func (p phoneStore) Devices() []phone.Device { return slices.Clone(p.s.State().Phones) }

func (p phoneStore) Add(d phone.Device) error {
	return p.s.update(func(st *State) error { st.Phones = append(st.Phones, d); return nil }, false)
}

func (p phoneStore) Remove(id string) error {
	return p.s.update(func(st *State) error {
		n := slices.DeleteFunc(st.Phones, func(d phone.Device) bool { return d.ID == id })
		if len(n) == len(st.Phones) {
			return notFound("no phone %q", id)
		}
		st.Phones = n
		return nil
	}, false)
}

func (p phoneStore) Touch(id, when string) error {
	return p.s.update(func(st *State) error {
		for i := range st.Phones {
			if st.Phones[i].ID == id {
				st.Phones[i].LastUsed = when
			}
		}
		return nil
	}, false)
}

// phone is the module's service (made once).
func (s *Server) phone() *phone.Service {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.phoneSvc == nil {
		s.phoneSvc = &phone.Service{Store: phoneStore{s}, Origin: s.Origin, Now: s.now, Enabled: func(name string) bool {
			u, err := s.Eng.User(name)
			return err == nil && u.Enabled && name != BindAccount
		}}
	}
	return s.phoneSvc
}

// qrData draws a QR code as an <img> data URL.
func qrData(text string) string {
	c, err := qr.Encode(text)
	if err != nil {
		return ""
	}
	return "data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString([]byte(c.SVG(4)))
}

func (s *Server) phoneOff() error {
	if !s.moduleOn("phone") {
		return notFound("the phone module is off")
	}
	return nil
}

// ---- the phone's calls (no login: the code or the signature is the proof) ----

func (s *Server) postPhoneEnroll(r *http.Request) (any, error) {
	if err := s.phoneOff(); err != nil {
		return nil, err
	}
	var req struct {
		Code, Name, Platform, Key, Sig string
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	d, err := s.phone().Enrol(req.Code, strings.TrimSpace(req.Name), req.Platform, req.Key, req.Sig)
	if err != nil {
		s.Log.Printf("phone enrol from %s: %v", r.RemoteAddr, err)
		return nil, coded(http.StatusForbidden, "enrol", "%v", err)
	}
	s.Log.Printf("phone %s (%s) enrolled for %s from %s", d.ID, d.Name, d.User, r.RemoteAddr)
	display := d.User
	if u, err := s.Eng.User(d.User); err == nil && u.DisplayName != "" {
		display = u.DisplayName
	}
	brand, _ := oidcDir{s}.Brand()
	return map[string]any{"device": d.ID, "user": d.User, "display_name": display, "origin": s.Origin(), "brand": brand}, nil
}

func (s *Server) postPhoneApprove(r *http.Request) (any, error) {
	if err := s.phoneOff(); err != nil {
		return nil, err
	}
	var req struct {
		C, N, Device, Sig string
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.phone().Approve(req.C, req.N, req.Device, req.Sig); err != nil {
		s.Log.Printf("phone approve from %s: %v", r.RemoteAddr, err)
		return nil, coded(http.StatusForbidden, "approve", "%v", err)
	}
	return map[string]any{"ok": true}, nil
}

// ---- keelAuth's own login page ----

func (s *Server) postPhoneLogin(r *http.Request) (any, error) {
	if err := s.phoneOff(); err != nil {
		return nil, err
	}
	c := s.phone().NewChallenge()
	// url: what the QR code says (the page shows the code; a phone that cannot scan, or a
	// test, can take the text)
	return map[string]any{"id": c.ID, "poll": c.Poll, "qr": qrData(c.URL), "url": c.URL, "expires_s": int(time.Until(c.Expires).Seconds())}, nil
}

// getPhoneLogin: the page's poll; approved = the session (like POST /login).
func (s *Server) getPhoneLogin(r *http.Request) (any, error) {
	if err := s.phoneOff(); err != nil {
		return nil, err
	}
	state, user, dev := s.phone().Take(r.PathValue("id"), r.URL.Query().Get("poll"))
	if state != "approved" {
		return map[string]any{"state": state}, nil
	}
	u, err := s.Eng.User(user)
	if err != nil || !u.Enabled {
		return nil, coded(http.StatusUnauthorized, "disabled", "this account is disabled")
	}
	in := s.loginAs(r, u, "phone "+dev)
	return map[string]any{"state": "approved", "session": in}, nil
}

// PhoneChallenge / PhonePoll: the oidc module's login page (oidc.PhoneLogin).
func (s *Server) PhoneChallenge() (id, poll, qrURL string, ok bool) {
	if !s.moduleOn("phone") {
		return "", "", "", false
	}
	c := s.phone().NewChallenge()
	return c.ID, c.Poll, qrData(c.URL), true
}

func (s *Server) PhonePoll(id, poll string) (state, user string) {
	if !s.moduleOn("phone") {
		return "expired", ""
	}
	state, user, dev := s.phone().Take(id, poll)
	if state == "approved" {
		s.Log.Printf("sso login %s by phone %s", user, dev)
	}
	return state, user
}

// ---- the page: own phones, an administrator's view of anybody's ----

type phoneOut struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Name     string `json:"name"`
	Platform string `json:"platform,omitempty"`
	Created  string `json:"created"`
	LastUsed string `json:"last_used,omitempty"`
}

// phoneUser: whose phones: the caller's, or ?user= / {"user"} for an administrator.
func (s *Server) phoneUser(r *http.Request, want string) (string, error) {
	c := caller(r)
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" || want == c.Name {
		if c.Name == "" {
			return "", bad("whose phones: user")
		}
		return c.Name, nil
	}
	if !c.Admin {
		return "", coded(http.StatusForbidden, "not_admin", "only an administrator sees other people's phones")
	}
	if _, err := s.Eng.User(want); err != nil {
		return "", notFound("no user %q", want)
	}
	return want, nil
}

func (s *Server) getPhones(r *http.Request) (any, error) {
	user, err := s.phoneUser(r, r.URL.Query().Get("user"))
	if err != nil {
		return nil, err
	}
	out := []phoneOut{}
	for _, d := range s.State().Phones {
		if d.User == user {
			out = append(out, phoneOut{d.ID, d.User, d.Name, d.Platform, d.Created, d.LastUsed})
		}
	}
	return map[string]any{"phones": out, "enabled": s.moduleOn("phone"), "user": user}, nil
}

func (s *Server) postPhoneEnrolment(r *http.Request) (any, error) {
	if err := s.phoneOff(); err != nil {
		return nil, err
	}
	if err := s.elsewhere(caller(r)); err != nil {
		return nil, err
	}
	var req struct {
		User string `json:"user"`
	}
	if err := decodeOpt(r, &req); err != nil {
		return nil, err
	}
	user, err := s.phoneUser(r, req.User)
	if err != nil {
		return nil, err
	}
	e := s.phone().NewEnrolment(user)
	return map[string]any{"id": e.ID, "user": user, "qr": qrData(e.URL), "url": e.URL, "expires_s": int(time.Until(e.Expires).Seconds())}, nil
}

func (s *Server) getPhoneEnrolment(r *http.Request) (any, error) {
	state, d := s.phone().EnrolmentState(r.PathValue("id"))
	out := map[string]any{"state": state}
	if d != nil {
		out["phone"] = phoneOut{d.ID, d.User, d.Name, d.Platform, d.Created, d.LastUsed}
	}
	return out, nil
}

func (s *Server) deletePhone(r *http.Request) (any, error) {
	id := r.PathValue("id")
	var owner string
	for _, d := range s.State().Phones {
		if d.ID == id {
			owner = d.User
		}
	}
	if owner == "" {
		return nil, notFound("no phone %q", id)
	}
	if _, err := s.phoneUser(r, owner); err != nil {
		return nil, err
	}
	if err := (phoneStore{s}).Remove(id); err != nil {
		return nil, err
	}
	s.Log.Printf("phone %s of %s removed by %s", id, owner, caller(r).Name)
	return map[string]any{"ok": true}, nil
}
