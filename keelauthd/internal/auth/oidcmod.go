package auth

import (
	"crypto/subtle"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/module/oidc"
)

// The oidc module (docs/01 "2026-10-30 晚", 模块化): with the native engine keelauthd is the
// OpenID Connect provider itself, on the origin's port (8443, where Kanidm's was), through
// internal/module/oidc. With Kanidm, Kanidm provides and this is off.

// oidcDir is the account store as the provider reads it.
type oidcDir struct{ s *Server }

func (d oidcDir) Origin() string { return d.s.Origin() }
func (d oidcDir) Domain() string { return d.s.State().Domain }

func (d oidcDir) Brand() (string, string) {
	b := d.s.State().Brand
	logo := ""
	if len(b.Logo) > 0 {
		logo = "/brand/logo?v=" + b.Tag()
	}
	return b.NameFor("en"), logo
}

func (d oidcDir) Clients() []engine.OAuth2 {
	cs, err := d.s.Eng.OAuth2s()
	if err != nil {
		return nil
	}
	return cs
}

func (d oidcDir) Client(id string) (*engine.OAuth2, bool) {
	c, err := d.s.Eng.OAuth2(id)
	if err != nil {
		return nil, false
	}
	return c, true
}

func (d oidcDir) CheckSecret(id, secret string) bool {
	want, err := d.s.Eng.OAuth2Secret(id, false)
	return err == nil && want != "" && subtle.ConstantTimeCompare([]byte(want), []byte(secret)) == 1
}

func (d oidcDir) CheckPassword(name, pw string) bool {
	ok, err := d.s.Eng.CheckPassword(name, pw)
	return err == nil && ok
}

func (d oidcDir) Allowed(name, client string) bool { return d.s.allowed(name, accessOIDC+client) }

func (d oidcDir) Person(name string) (oidc.Person, bool) {
	u, err := d.s.Eng.User(name)
	if err != nil || !u.Enabled || name == BindAccount {
		return oidc.Person{}, false
	}
	_, _, memberOf := ldapDir{d.s}.flat()
	gs := memberOf[name]
	if gs == nil {
		gs = []string{}
	}
	mail := u.Mail
	if as := d.s.accessChecker().addresses(name); mail == "" && len(as) > 0 {
		mail = as[0]
	}
	return oidc.Person{Name: u.Name, DisplayName: u.DisplayName, Mail: mail, UUID: u.UUID, Groups: gs}, true
}

// oidcListening: the module's listener is up (status).
var oidcListening atomic.Bool

// oidcProvider makes the provider (once) with its keys in the data directory.
func (s *Server) oidcProvider() (*oidc.Server, error) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.oidcSrv == nil {
		dir := "" // keys in memory for tests; on the VM in the data directory
		if s.Real {
			dir = s.Data
		}
		p, err := oidc.New(oidcDir{s}, dir, s.Log)
		if err != nil {
			return nil, err
		}
		s.oidcSrv = p
	}
	return s.oidcSrv, nil
}

// oidcHandler is what the origin's port serves: the provider, and the brand's logo for its
// pages.
func (s *Server) oidcHandler(p *oidc.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/brand/logo" {
			s.getBrandLogo(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/phone/") { // the phone's calls (phonemod.go): the QR code names this origin
			s.Handler().ServeHTTP(w, r)
			return
		}
		p.ServeHTTP(w, r)
	})
}

// serveOIDC runs the provider on the origin's port over TLS (the web certificate).
func (s *Server) serveOIDC(port int) {
	p, err := s.oidcProvider()
	if err != nil {
		s.Log.Printf("oidc: %v", err)
		return
	}
	tc := &tls.Config{GetCertificate: s.serverCert, MinVersion: tls.VersionTLS12}
	addr := fmt.Sprintf(":%d", port)
	h := s.oidcHandler(p)
	for i := 0; ; i++ {
		if !s.moduleOn("oidc") { // switched off (modules.go): wait for the switch
			time.Sleep(2 * time.Second)
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if i%12 == 0 {
				s.Log.Printf("oidc: listen %s: %v (trying again every 5 s)", addr, err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		s.Log.Printf("oidc: listening on %s (HTTPS)", addr)
		srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc, ErrorLog: nil}
		s.setModuleCloser("oidc", srv)
		oidcListening.Store(true)
		err = srv.ServeTLS(ln, "", "")
		oidcListening.Store(false)
		s.setModuleCloser("oidc", nil)
		if !s.moduleOn("oidc") {
			s.Log.Printf("oidc: stopped (module off)")
			continue
		}
		s.Log.Printf("oidc: %v", err)
		time.Sleep(5 * time.Second)
	}
}

// oidcSrvIfAny is the provider when it was made.
func (s *Server) oidcSrvIfAny() *oidc.Server {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	return s.oidcSrv
}

// PhoneOn / PhoneChallenge / PhonePoll: the phone module on the oidc module's login page
// (oidc.PhoneLogin, phonemod.go).
func (d oidcDir) PhoneOn() bool                                  { return d.s.moduleOn("phone") }
func (d oidcDir) PhoneChallenge() (id, poll, qr string, ok bool) { return d.s.PhoneChallenge() }
func (d oidcDir) PhonePoll(id, poll string) (state, user string) { return d.s.PhonePoll(id, poll) }
