package auth

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
)

// setOrigin gives the running server a seed with the origin mode and (when lan != "") a fixed
// LAN address, then brings it up again (the certificate and Kanidm's config follow).
func setOrigin(t *testing.T, r *rig, mode, lan string) {
	t.Helper()
	sd := testSeed(r.key)
	sd.Origin = mode
	if lan != "" {
		sd.Lan = &SeedLan{Mode: "static", Address: lan, Gateway: "192.0.2.1"}
	}
	r.s.hmu.Lock()
	r.s.seed = sd
	r.s.hmu.Unlock()
	// the test server is not Real (BringUp makes no certificates): do what bringUp does
	if _, err := r.s.EnsureTLS(r.s.State().Domain, ""); err != nil {
		t.Fatal(err)
	}
}

func serverCert(t *testing.T, r *rig) (ip bool, names []string) {
	c := parseCert(t, r.sy.Files[filepath.Join(r.s.tlsDir(), serverCertFile)])
	return c.VerifyHostname("192.0.2.10") == nil, c.DNSNames
}

func TestIPOrigin(t *testing.T) {
	r := newRig(t)
	// domain mode (default): as before
	if _, err := r.s.EnsureTLS("auth.office.lan", ""); err != nil {
		t.Fatal(err)
	}
	if o := r.s.Origin(); o != "https://auth.office.lan:8443" {
		t.Errorf("origin %s", o)
	}
	if ip, _ := serverCert(t, r); ip {
		t.Error("domain mode: the certificate has the LAN address")
	}
	st := r.ok("GET", "/v1/status", nil)
	if st["origin"] != "https://auth.office.lan:8443" || st["origin_mode"] != "domain" {
		t.Errorf("status %v %v", st["origin"], st["origin_mode"])
	}

	// ip mode with a fixed address
	setOrigin(t, r, "ip", "192.0.2.10/24")
	if o := r.s.Origin(); o != "https://192.0.2.10:8443" {
		t.Errorf("origin %s", o)
	}
	if ip, _ := serverCert(t, r); !ip {
		t.Error("ip mode: no IP SAN")
	}
	c := parseCert(t, r.sy.Files[filepath.Join(r.s.tlsDir(), serverCertFile)])
	if c.VerifyHostname("auth.office.lan") != nil {
		t.Error("ip mode lost the domain name")
	}
	cfg := r.s.KanidmConfig(r.s.State(), false)
	if !strings.Contains(cfg, `origin = "https://192.0.2.10:8443"`) || !strings.Contains(cfg, `domain = "auth.office.lan"`) {
		t.Errorf("config:\n%s", cfg)
	}
	st = r.ok("GET", "/v1/status", nil)
	if st["origin"] != "https://192.0.2.10:8443" || st["origin_mode"] != "ip" {
		t.Errorf("status %v %v", st["origin"], st["origin_mode"])
	}
	o := r.ok("POST", "/v1/oidc", map[string]any{"name": "wiki", "redirect_urls": []string{"https://wiki.example.com/cb"}})
	if o["issuer"] != "https://192.0.2.10:8443/oauth2/openid/wiki" ||
		o["discovery_url"] != "https://192.0.2.10:8443/oauth2/openid/wiki/.well-known/openid-configuration" {
		t.Errorf("oidc %v", o)
	}
	l := r.ok("GET", "/v1/oidc", nil)
	if l["issuer_base"] != "https://192.0.2.10:8443/oauth2/openid/" || l["origin_mode"] != "ip" || l["domain"] != "auth.office.lan" {
		t.Errorf("oidc list %v", l)
	}
	if ld := r.ok("GET", "/v1/ldap", nil); ld["host"] != "192.0.2.10" {
		t.Errorf("ldap host %v", ld["host"])
	}
	for _, a := range r.s.Alerts() {
		if a.Code == "origin_ip_fallback" {
			t.Error("alert with a fixed address")
		}
	}

	// the address changes: a new certificate with the new one
	setOrigin(t, r, "ip", "192.0.2.20/24")
	c = parseCert(t, r.sy.Files[filepath.Join(r.s.tlsDir(), serverCertFile)])
	if c.VerifyHostname("192.0.2.20") != nil || c.VerifyHostname("192.0.2.10") == nil {
		t.Errorf("SANs after the change: %v", c.IPAddresses)
	}
	// back to the domain: the address leaves the certificate
	setOrigin(t, r, "domain", "192.0.2.20/24")
	c = parseCert(t, r.sy.Files[filepath.Join(r.s.tlsDir(), serverCertFile)])
	for _, ip := range c.IPAddresses {
		if !ip.IsLoopback() && !ip.Equal(net.ParseIP("169.254.77.3")) {
			t.Errorf("domain mode: certificate has %v", ip)
		}
	}
	if r.s.Origin() != "https://auth.office.lan:8443" {
		t.Error("origin did not go back")
	}
}

func TestIPOriginNeedsFixedAddress(t *testing.T) {
	r := newRig(t)
	setOrigin(t, r, "ip", "") // DHCP
	if o := r.s.Origin(); o != "https://auth.office.lan:8443" {
		t.Errorf("origin %s", o)
	}
	if ip, _ := serverCert(t, r); ip {
		t.Error("fallback: the certificate has the LAN address")
	}
	st := r.ok("GET", "/v1/status", nil)
	if st["origin_mode"] != "domain" {
		t.Errorf("mode %v", st["origin_mode"])
	}
	found := false
	for _, a := range r.s.Alerts() {
		if a.Code == "origin_ip_fallback" && strings.Contains(a.Text, "IP origin needs a fixed LAN address") {
			found = true
		}
	}
	if !found {
		t.Error("no fallback alert")
	}
	// standalone (no seed): domain, no alert
	r.s.hmu.Lock()
	r.s.seed = nil
	r.s.hmu.Unlock()
	if r.s.Origin() != "https://auth.office.lan:8443" {
		t.Error("standalone origin")
	}
}

func TestSeedOrigin(t *testing.T) {
	base := `{"keelauth_seed":1,"key":"` + strings.Repeat("ab", 32) + `","port":8441,"keel":["https://169.254.77.1:443"],"fingerprint":"` + strings.TrimSuffix(strings.Repeat("AB:", 32), ":") + `",`
	sd, err := ParseSeed([]byte(base + `"origin":"ip","lan":{"mode":"static","address":"192.0.2.10/24"}}`))
	if err != nil || sd.Origin != "ip" || sd.Lan.Address != "192.0.2.10/24" {
		t.Fatalf("%v %+v", err, sd)
	}
	for _, b := range []string{`"origin":"dns"}`, `"lan":{"mode":"static","address":"nope"}}`} {
		if _, err := ParseSeed([]byte(base + b)); err == nil {
			t.Errorf("%s accepted", b)
		}
	}
}
