package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"keelauth/internal/engine"
)

// ---- LDAP device accounts (D4)

func TestDeviceAccounts(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "password": "Winter-Lantern-4471"})
	d := r.ok("POST", "/v1/ldap/devices", map[string]any{"name": "printer-2f", "description": "Copier, 2nd floor"})
	tok, _ := d["password"].(string)
	if d["bind_dn"] != "dn=token" || tok == "" || tok != r.eng.Token("printer-2f") {
		t.Fatalf("made: %v (engine token %q)", d, r.eng.Token("printer-2f"))
	}
	sas, _ := r.eng.ServiceAccounts()
	if len(sas) != 1 || !slices.Equal(sas[0].Groups, []string{engine.MailRead, engine.UnixRead}) || sas[0].DisplayName != "Copier, 2nd floor" {
		t.Fatalf("service account: %+v", sas)
	}
	// listed without the password; in GET /v1/ldap too
	l := r.ok("GET", "/v1/ldap/devices", nil)
	ds := l["devices"].([]any)
	if len(ds) != 1 || ds[0].(map[string]any)["password"] != nil || ds[0].(map[string]any)["name"] != "printer-2f" {
		t.Fatalf("list: %v", l)
	}
	if ld := r.ok("GET", "/v1/ldap", nil); len(ld["devices"].([]any)) != 1 || ld["device_bind_dn"] != "dn=token" {
		t.Fatalf("ldap: %v", ld)
	}
	// users are not device accounts and the other way round
	for _, c := range []struct {
		name string
		code int
	}{{"printer-2f", 409}, {"alice", 409}, {"keelauth-ldap", 400}, {"admin", 400}, {"Bad Name", 400}, {"dn", 400}} {
		if code, out, _ := r.call("POST", "/v1/ldap/devices", "", map[string]any{"name": c.name}); code != c.code {
			t.Errorf("device %q: %d %v, want %d", c.name, code, out, c.code)
		}
	}
	if code, _, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "printer-2f", "password": "Winter-Lantern-4471"}); code != 409 {
		t.Errorf("a user with a device's name: %d", code)
	}
	// a new password replaces the old
	n := r.ok("POST", "/v1/ldap/devices/printer-2f/password", nil)
	if n["password"] == tok || n["password"] != r.eng.Token("printer-2f") {
		t.Fatalf("new password: %v", n)
	}
	// the engine lost it (an older backup restored): a new password makes it again
	r.eng.DeleteServiceAccount("printer-2f")
	if l := r.ok("GET", "/v1/ldap/devices", nil); l["devices"].([]any)[0].(map[string]any)["missing"] != true {
		t.Fatalf("missing not shown: %v", l)
	}
	if n := r.ok("POST", "/v1/ldap/devices/printer-2f/password", nil); n["password"] != r.eng.Token("printer-2f") || n["password"] == "" {
		t.Fatalf("made again: %v", n)
	}
	// examples carry the device, the base DN, the bind DN and the placeholder
	ex := r.ok("GET", "/v1/ldap/examples?device=printer-2f", nil)
	ids := []string{}
	for _, e := range ex["examples"].([]any) {
		m := e.(map[string]any)
		ids = append(ids, m["id"].(string))
		txt := m["text"].(string)
		if !strings.Contains(txt, "dc=auth,dc=office,dc=lan") || !strings.Contains(txt, "dn=token") || !strings.Contains(txt, DevicePasswordHolder) {
			t.Errorf("example %s: %s", m["id"], txt)
		}
	}
	if !slices.Equal(ids, []string{"sssd", "printer", "dovecot", "dovecot23", "postfix", "gitlab", "redmine"}) {
		t.Fatalf("examples: %v", ids)
	}
	if code, _, _ := r.call("GET", "/v1/ldap/examples?device=nope", "", nil); code != 404 {
		t.Errorf("examples for no device: %d", code)
	}
	// delete
	r.ok("DELETE", "/v1/ldap/devices/printer-2f", nil)
	if sas, _ := r.eng.ServiceAccounts(); len(sas) != 0 || len(r.s.State().Devices) != 0 {
		t.Fatalf("after delete: %v %v", sas, r.s.State().Devices)
	}
	if code, _, _ := r.call("DELETE", "/v1/ldap/devices/printer-2f", "", nil); code != 404 {
		t.Errorf("delete twice: %d", code)
	}
	// MCP has the tools
	mt := "Bearer " + r.ok("POST", "/v1/tokens", map[string]any{"name": "claude"})["token"].(string)
	_, out := mcpCall(r, mt, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	b := toJSON(out)
	for _, n := range []string{"ldap_info", "ldap_device_add", "ldap_device_password", "ldap_device_delete", "ldap_examples", "cert_status"} {
		if !strings.Contains(b, `"`+n+`"`) {
			t.Errorf("MCP has no %s", n)
		}
	}
	_, out = mcpCall(r, mt, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"ldap_device_add","arguments":{"name":"gitlab"}}}`)
	if b := toJSON(out); !strings.Contains(b, "dn=token") || r.eng.Token("gitlab") == "" || !strings.Contains(b, r.eng.Token("gitlab")) {
		t.Fatalf("MCP ldap_device_add: %s", b)
	}
	_, out = mcpCall(r, mt, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ldap_info","arguments":{}}}`)
	if b := toJSON(out); strings.Contains(b, "bind_password") || !strings.Contains(b, "gitlab") {
		t.Fatalf("MCP ldap_info: %s", b)
	}
}

// ---- certificates (D4)

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newTestCA(t *testing.T, cn string, parent *testCA) *testCA {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	pc, pk := tmpl, crypto.Signer(k)
	if parent != nil {
		pc, pk = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, pc, k.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, k}
}

// leaf makes a server certificate; kind "rsa1" = PKCS#1 key PEM, "ec" = SEC 1, else PKCS#8.
func (ca *testCA) leaf(t *testing.T, names []string, until time.Time, kind string) (cpem, keyPEM []byte, c *x509.Certificate) {
	t.Helper()
	var k crypto.Signer
	var kp []byte
	switch kind {
	case "ec":
		e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(e)
		k, kp = e, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	case "rsa1":
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		k, kp = rk, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)})
	default:
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKCS8PrivateKey(rk)
		k, kp = rk, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, k.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ = x509.ParseCertificate(der)
	return certPEM(der), kp, c
}

func TestOfficeCertificate(t *testing.T) {
	r := newRig(t)
	SystemRoots = x509.NewCertPool() // no public CAs in the test
	t.Cleanup(func() { SystemRoots = nil })
	if _, err := r.s.EnsureTLS("auth.office.lan", ""); err != nil {
		t.Fatal(err)
	}
	ownChain := string(r.sy.Files[r.s.tlsPath(chainFile)])
	if string(r.sy.Files[r.s.tlsPath(useServerChain)]) != ownChain || r.sy.Files[r.s.tlsPath(useRadiusKey)] == nil {
		t.Fatal("the use files are not the own certificates")
	}
	if !strings.Contains(r.s.KanidmConfig(r.s.State(), false), useServerChain) {
		t.Fatal("Kanidm does not read the use files")
	}
	c := r.ok("GET", "/v1/certs", nil)
	if c["in_use"] != "own" || c["anchor"].(map[string]any)["sha256"] != c["own_ca"].(map[string]any)["sha256"] {
		t.Fatalf("own: %v", c)
	}
	root := newTestCA(t, "Office Root CA", nil)
	inter := newTestCA(t, "Office Issuing CA", root)
	year := time.Now().AddDate(1, 0, 0)
	up := func(cert, key []byte) (int, map[string]any) {
		code, out, _ := r.call("POST", "/v1/certs/office", "", map[string]any{"cert": string(cert), "key": string(key)})
		return code, out
	}
	// refused: other name, a key of another certificate, ended, no way to a root, a CA, garbage
	other, otherKey, _ := inter.leaf(t, []string{"mail.office.lan"}, year, "")
	good, goodKey, goodLeaf := inter.leaf(t, []string{"auth.office.lan"}, year, "")
	_, oldKey, _ := inter.leaf(t, []string{"auth.office.lan"}, time.Now().Add(time.Minute), "")
	rootPEM, interPEM := certPEM(root.cert.Raw), certPEM(inter.cert.Raw)
	full := append(append(append([]byte{}, good...), interPEM...), rootPEM...)
	for _, c := range []struct {
		what       string
		cert, key  []byte
		wantInText string
	}{
		{"other name", append(append(other, interPEM...), rootPEM...), otherKey, "not for auth.office.lan"},
		{"wrong key", full, otherKey, "belongs to none"},
		{"no chain", good, goodKey, "does not lead to a trusted root"},
		{"intermediate missing", append(append([]byte{}, good...), rootPEM...), goodKey, "does not lead to a trusted root"},
		{"no key", full, []byte("nothing"), "no private key"},
		{"no cert", []byte("x"), goodKey, "no certificate"},
		{"short RSA key", full, weakKey(t), "at least 2048"},
		{"passphrase", full, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"), "passphrase"},
	} {
		code, out := up(c.cert, c.key)
		if code != 400 || !strings.Contains(out["error"].(string), c.wantInText) || out["code"] != "bad_certificate" {
			t.Errorf("%s: %d %v", c.what, code, out)
		}
	}
	_ = oldKey
	if r.s.officeActive() || string(r.sy.Files[r.s.tlsPath(useServerChain)]) != ownChain {
		t.Fatal("a refused upload changed what is in use")
	}
	// ended: checked with the clock
	r.s.Now = func() time.Time { return year.Add(time.Hour) }
	if code, out := up(full, goodKey); code != 400 || !strings.Contains(out["error"].(string), "ended") {
		t.Errorf("ended: %d %v", code, out)
	}
	r.s.Now = nil
	// accepted: leaf + intermediate + root (the key in the certificate file is fine too)
	code, out := up(append(append([]byte{}, full...), goodKey...), nil)
	if code != 200 || out["in_use"] != "office" {
		t.Fatalf("upload: %d %v", code, out)
	}
	anchor := out["anchor"].(map[string]any)
	if anchor["subject"] != "CN=Office Root CA" || out["server"].(map[string]any)["subject"] != "CN=auth.office.lan" {
		t.Fatalf("after the upload: %v", out)
	}
	use := r.sy.Files[r.s.tlsPath(useServerChain)]
	cs, _ := pemCerts(use)
	if len(cs) != 3 || !cs[0].Equal(goodLeaf) || !cs[2].Equal(root.cert) || string(r.sy.Files[r.s.tlsPath(useRadiusChain)]) != string(use) {
		t.Fatalf("use files: %d certificates", len(cs))
	}
	if k, err := parseKey(r.sy.Files[r.s.tlsPath(useServerKey)]); err != nil || !samePublic(goodLeaf.PublicKey, k.Public()) {
		t.Fatalf("use key: %v", err)
	}
	// the page's certificate (keel-mcp's fingerprint) is the office's now
	if fp := r.s.Fingerprint(); fp != out["server"].(map[string]any)["sha256"] {
		t.Fatalf("fingerprint %s", fp)
	}
	// downloads: the root in use (PEM, DER), keelAuth's own on request, the Apple profile; public under /ca/
	get := func(path, auth string) (int, []byte, http.Header) {
		req := httptest.NewRequest("GET", path, nil)
		if auth != "none" {
			req.Header.Set("Authorization", "Bearer "+r.key)
		}
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.Bytes(), rec.Header()
	}
	if code, b, h := get("/v1/ca", ""); code != 200 || string(b) != string(rootPEM) || !strings.Contains(h.Get("Content-Disposition"), "office-ca.crt") {
		t.Fatalf("CA in use: %d %s", code, h)
	}
	if _, b, _ := get("/v1/ca?which=own", ""); !strings.Contains(string(b), "BEGIN CERTIFICATE") || string(b) == string(rootPEM) {
		t.Fatal("own CA")
	}
	if code, b, h := get("/ca/keelauth-ca.cer", "none"); code != 200 || string(b) != string(root.cert.Raw) || h.Get("Content-Type") != "application/pkix-cert" {
		t.Fatalf("DER without login: %d %s", code, h)
	}
	if code, b, _ := get("/ca/keelauth-ca.mobileconfig", "none"); code != 200 || !strings.Contains(string(b), base64.StdEncoding.EncodeToString(root.cert.Raw)[:64]) ||
		!strings.Contains(string(b), "com.apple.security.root") {
		t.Fatalf("mobileconfig: %d %s", code, b)
	}
	if code, _, _ := get("/v1/ca", "none"); code != 401 {
		t.Errorf("the API's CA without login: %d", code)
	}
	// RADIUS tells what phones check
	rad := r.ok("GET", "/v1/radius", nil)
	if rad["server_name"] != "auth.office.lan" || rad["ca"].(map[string]any)["subject"] != "CN=Office Root CA" || rad["office_cert"] != true {
		t.Fatalf("radius: %v", rad)
	}
	// alerts: 20 days before the end a warning, after it an error
	r.s.Now = func() time.Time { return year.AddDate(0, 0, -20) }
	if a := alertCodes(r.s.Alerts()); !slices.Contains(a, "cert_expiring") {
		t.Errorf("20 days before: %v", a)
	}
	r.s.Now = func() time.Time { return year.Add(time.Hour) }
	if a := alertCodes(r.s.Alerts()); !slices.Contains(a, "cert_expired") {
		t.Errorf("after the end: %v", a)
	}
	r.s.Now = nil
	if a := alertCodes(r.s.Alerts()); slices.Contains(a, "cert_expiring") || slices.Contains(a, "cert_expired") {
		t.Errorf("now: %v", a)
	}
	// back to keelAuth's own; the own files were never touched
	back := r.ok("DELETE", "/v1/certs/office", nil)
	if back["in_use"] != "own" || string(r.sy.Files[r.s.tlsPath(useServerChain)]) != ownChain || r.sy.Files[r.s.tlsPath(chainFile)] == nil {
		t.Fatalf("back: %v", back)
	}
	if code, _, _ := r.call("DELETE", "/v1/certs/office", "", nil); code != 404 {
		t.Errorf("back twice: %d", code)
	}
	// other key kinds: PKCS#1 RSA and EC (with a warning)
	for _, kind := range []string{"rsa1", "ec"} {
		c, k, _ := root.leaf(t, []string{"*.office.lan"}, year, kind)
		code, out := up(append(c, rootPEM...), k)
		if code != 200 {
			t.Fatalf("%s: %d %v", kind, code, out)
		}
		if kind == "ec" && !strings.Contains(toJSON(out["warnings"]), "ECDSA") {
			t.Errorf("no ECDSA warning: %v", out["warnings"])
		}
	}
	r.ok("DELETE", "/v1/certs/office", nil)
}

func weakKey(t *testing.T) []byte {
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func alertCodes(as []Alert) []string {
	var out []string
	for _, a := range as {
		out = append(out, a.Code)
	}
	return out
}

// TestPatchEAP: FreeRADIUS's eap module of an image before D4 is pointed at the use files.
func TestPatchEAP(t *testing.T) {
	r := newRig(t)
	r.s.Real = true
	defer func() { r.s.Real = false }()
	old := "eap {\n\ttls-config tls-common {\n\t\tprivate_key_file = /data/keelauth/tls/radius.key\n\t\tcertificate_file = /data/keelauth/tls/radius-chain.pem\n\t\tca_file = /data/keelauth/tls/ca.crt\n\t}\n}\n"
	r.sy.Files[RadiusEAP] = []byte(old)
	if ch, err := r.s.patchEAP(); err != nil || !ch {
		t.Fatalf("patch: %v %v", ch, err)
	}
	got := string(r.sy.Files[RadiusEAP])
	if !strings.Contains(got, "private_key_file = /data/keelauth/tls/use-radius.key") || !strings.Contains(got, "certificate_file = /data/keelauth/tls/use-radius-chain.pem") ||
		!strings.Contains(got, "ca_file = /data/keelauth/tls/ca.crt") {
		t.Fatalf("patched: %s", got)
	}
	if ch, _ := r.s.patchEAP(); ch {
		t.Fatal("patched twice")
	}
}
