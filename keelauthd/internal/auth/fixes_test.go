package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func parseCert(t *testing.T, b []byte) *x509.Certificate {
	t.Helper()
	p, _ := pem.Decode(b)
	if p == nil {
		t.Fatal("no PEM")
	}
	c, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The server certificate has no LAN address and stays when the addresses change; the RADIUS
// one is RSA 2048; the CA RSA 3072; a new domain makes both new (docs/02 section 7.6).
func TestCertificates(t *testing.T) {
	r := newRig(t)
	dir := r.s.tlsDir()
	if _, err := r.s.EnsureTLS("auth.office.lan", "169.254.77.3"); err != nil {
		t.Fatal(err)
	}
	ca := parseCert(t, r.sy.Files[filepath.Join(dir, caCertFile)])
	if k, ok := ca.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 3072 {
		t.Errorf("CA key %T", ca.PublicKey)
	}
	srv := parseCert(t, r.sy.Files[filepath.Join(dir, serverCertFile)])
	if _, ok := srv.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Errorf("server key %T", srv.PublicKey)
	}
	for _, ip := range srv.IPAddresses {
		if !ip.Equal(net.ParseIP("127.0.0.1")) && !ip.Equal(net.ParseIP("169.254.77.3")) {
			t.Errorf("server certificate has %v", ip)
		}
	}
	if srv.VerifyHostname("auth.office.lan") != nil || srv.CheckSignatureFrom(ca) != nil {
		t.Error("server certificate: name or signature")
	}
	rad := parseCert(t, r.sy.Files[filepath.Join(dir, radiusCertFile)])
	if k, ok := rad.PublicKey.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
		t.Errorf("RADIUS key %T", rad.PublicKey)
	}
	if rad.CheckSignatureFrom(ca) != nil || rad.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || rad.Subject.CommonName != "auth.office.lan" {
		t.Error("RADIUS certificate: signature, EKU or CN")
	}
	fp := r.s.Fingerprint()
	// the LAN address changes (DHCP) and the internal one too: nothing new
	r.sy.Handle = func(line, stdin string) (string, error, bool) {
		if line == "ifconfig -a inet" {
			return "vtnet0: flags=8843<UP>\n\tinet 192.168.1.77 netmask 0xffffff00\n", nil, true
		}
		return "", nil, false
	}
	ch, err := r.s.EnsureTLS("auth.office.lan", "169.254.77.9")
	if err != nil || ch.Server || ch.Radius || r.s.Fingerprint() != fp {
		t.Errorf("address change made new certificates: %+v %v", ch, err)
	}
	ch, err = r.s.EnsureTLS("auth2.office.lan", "")
	if err != nil || !ch.Server || !ch.Radius || r.s.Fingerprint() == fp {
		t.Errorf("domain change: %+v %v", ch, err)
	}
	if parseCert(t, r.sy.Files[filepath.Join(dir, caCertFile)]).Equal(ca) == false {
		t.Error("the CA changed")
	}
}

// Sessions survive a restart of keelauthd (a new Server on the same data); logout and stale
// ones do not.
func TestSessionsSurviveRestart(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026", "groups": []string{AdminGroup}})
	ck, _, code := login(r, "anna", "Keel-Auth-2026")
	if code != 200 {
		t.Fatalf("login %d", code)
	}
	ck2, _, _ := login(r, "anna", "Keel-Auth-2026")
	r.call("POST", "/logout", "cookie:"+ck2+":", nil)
	if b := string(r.sy.Files[filepath.Join(r.s.Data, sessionFile)]); b == "" || strings.Contains(b, ck) {
		t.Fatalf("sessions file %q", b)
	}
	s2 := startServer(t, r.sy, r.eng, testSeed(r.key))
	r.s, r.h = s2, s2.Handler()
	if code, out, _ := r.call("GET", "/session", "cookie:"+ck+":", nil); code != 200 || out["name"] != "anna" {
		t.Errorf("after restart: %d %v", code, out)
	}
	if code, _, _ := r.call("GET", "/session", "cookie:"+ck2+":", nil); code != 401 {
		t.Errorf("logged-out session after restart: %d", code)
	}
}

func TestSockstatAndMount(t *testing.T) {
	out := `USER     COMMAND    PID   FD  PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
kanidmd  kanidmd     812  12  tcp4   *:8443                *:*
kanidmd  kanidmd     812  13  tcp4   *:636                 *:*
freeradius radiusd   901  6   udp4   *:1812                *:*
root     sshd        700  4   tcp4   *:22                  *:*
`
	if !SockstatHas(out, "kanidmd", "tcp", 636) || !SockstatHas(out, "radiusd", "udp", 1812) {
		t.Error("ports not found")
	}
	if SockstatHas(out, "radiusd", "tcp", 1812) || SockstatHas(out, "kanidmd", "tcp", 22) || SockstatHas(out, "radiusd", "udp", 1813) {
		t.Error("wrong match")
	}
	m := "kasys/ROOT/v1 / zfs rw 0 0\nkadata /data zfs rw,noatime 0 0\ntmpfs /tmp tmpfs rw 0 0\n"
	if ParseMountType(m, "/data/keelauth/kanidm") != "zfs" || ParseMountType(m, "/tmp/x") != "tmpfs" || ParseMountType(m, "/datax") != "zfs" {
		t.Error("mount types")
	}
	if ParseMountType("/dev/vtbd0p2 / ufs rw 1 1\n", "/data/keelauth") != "ufs" {
		t.Error("ufs root")
	}
}

// Until Serve's first bring-up is over the account API answers 503 "starting" (keel making its
// first administrator on the first host got 400 "no group keelauth-admins" from a not yet prepared Kanidm,
// keelOS docs/54 §4.5); the status still answers.
func TestStartingGate(t *testing.T) {
	r := newRig(t)
	r.s.starting.Store(true)
	for _, p := range [][2]string{{"GET", "/v1/users/keeladmin"}, {"POST", "/v1/users"}} {
		code, out, _ := r.call(p[0], p[1], "", map[string]any{"name": "x"})
		if code != 503 || out["code"] != "starting" {
			t.Fatalf("%s %s while starting: %d %v", p[0], p[1], code, out)
		}
	}
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "a", "password": "b"}); code != 503 {
		t.Fatalf("login while starting: %d %v", code, out)
	}
	r.ok("GET", "/v1/status", nil)
	r.s.starting.Store(false)
	if code, _, _ := r.call("GET", "/v1/users/keeladmin", "", nil); code != 404 {
		t.Fatalf("after bring-up: %d", code)
	}
}
