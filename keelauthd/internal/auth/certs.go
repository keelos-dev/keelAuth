package auth

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"
)

// The certificates in use (docs/02 section 7.10). keelAuth's own (tls.go) are the default; an
// office with its own certificate for keelAuth's domain (its own CA, or a public one) uploads
// it with its key, and Kanidm (HTTPS, LDAPS), FreeRADIUS (PEAP) and keelauthd's page take it.
// Taking it back returns to keelAuth's own, which are kept (and renewed) meanwhile.
//
// Kanidm, FreeRADIUS and the page read the "use" files, which keelauthd writes from whichever
// is in use (applyCerts), so the own files are never overwritten.

const (
	officeDir         = "office"
	officeChainFile   = "office/chain.pem" // leaf, intermediates and the root, in that order
	officeKeyFile     = "office/key.pem"
	officeAnchorFile  = "office/anchor.pem" // the root the chain leads to: what devices trust
	officeMetaFile    = "office/uploaded"   // when (RFC 3339)
	useServerChain    = "use-server-chain.pem"
	useServerKey      = "use-server.key"
	useRadiusChain    = "use-radius-chain.pem"
	useRadiusKey      = "use-radius.key"
	certWarnBefore    = 30 * 24 * time.Hour
	RadiusEAP         = RaddbDir + "/mods-available/eap"
	officeMaxPEMBytes = 256 << 10
)

func (s *Server) tlsPath(name string) string { return filepath.Join(s.tlsDir(), name) }

// officeActive: the office's certificate is in use.
func (s *Server) officeActive() bool {
	_, err := s.Sys.ReadFile(s.tlsPath(officeChainFile))
	return err == nil
}

// applyCerts writes the use files from what is in use; it reports which changed (their users
// must restart).
func (s *Server) applyCerts() (TLSChanged, error) {
	var ch TLSChanged
	srvChain, srvKey, radChain, radKey := chainFile, serverKeyFile, radiusChainFile, radiusKeyFile
	if s.officeActive() {
		srvChain, srvKey, radChain, radKey = officeChainFile, officeKeyFile, officeChainFile, officeKeyFile
	}
	cp := func(from, to string, perm uint32) (bool, error) {
		b, err := s.Sys.ReadFile(s.tlsPath(from))
		if err != nil {
			return false, err
		}
		return s.writeIfChanged(s.tlsPath(to), string(b), perm)
	}
	var err error
	var a, b bool
	if a, err = cp(srvChain, useServerChain, 0o644); err != nil {
		return ch, err
	}
	if b, err = cp(srvKey, useServerKey, 0o640); err != nil {
		return ch, err
	}
	ch.Server = a || b
	if a, err = cp(radChain, useRadiusChain, 0o644); err != nil {
		return ch, err
	}
	if b, err = cp(radKey, useRadiusKey, 0o640); err != nil {
		return ch, err
	}
	ch.Radius = a || b
	if ch.Server || ch.Radius {
		s.tlsPerms()
	}
	if changed, err := s.patchEAP(); err != nil {
		s.Log.Printf("tls: FreeRADIUS's eap module: %v", err)
	} else if changed {
		ch.Radius = true
	}
	return ch, nil
}

// patchEAP points FreeRADIUS's EAP module at the use files (images before D4 named radius.key
// and radius-chain.pem). It reports whether it changed the file.
func (s *Server) patchEAP() (bool, error) {
	if !s.Real {
		return false, nil
	}
	b, err := s.Sys.ReadFile(RadiusEAP)
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "private_key_file = ") && strings.HasSuffix(t, "/"+radiusKeyFile):
			lines[i] = strings.TrimSuffix(l, radiusKeyFile) + useRadiusKey
		case strings.HasPrefix(t, "certificate_file = ") && strings.HasSuffix(t, "/"+radiusChainFile):
			lines[i] = strings.TrimSuffix(l, radiusChainFile) + useRadiusChain
		}
	}
	return s.writeIfChanged(RadiusEAP, strings.Join(lines, "\n"), 0o640)
}

// ---- reading certificates

// CertInfo is a certificate as the page and devices need it.
type CertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	Names     []string `json:"names,omitempty"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	SHA256    string   `json:"sha256"`
	SHA1      string   `json:"sha1"` // Windows calls it the thumbprint
	Key       string   `json:"key"`
	CA        bool     `json:"ca,omitempty"`
}

func (s *Server) certInfo(c *x509.Certificate) CertInfo {
	s256 := sha256.Sum256(c.Raw)
	s1 := sha1.Sum(c.Raw)
	names := append([]string{}, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		names = append(names, ip.String())
	}
	return CertInfo{Subject: c.Subject.String(), Issuer: c.Issuer.String(), Names: names,
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339), NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft: int(c.NotAfter.Sub(s.now()).Hours() / 24), SHA256: FormatFingerprint(s256[:]), SHA1: FormatFingerprint(s1[:]),
		Key: keyName(c.PublicKey), CA: c.IsCA}
}

func keyName(k any) string {
	switch k := k.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return "?"
}

// pemCerts parses every CERTIFICATE block.
func pemCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p == nil {
			return out, nil
		}
		if p.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a certificate cannot be read: %v", err)
		}
		out = append(out, c)
	}
}

func (s *Server) readCerts(name string) ([]*x509.Certificate, error) {
	b, err := s.Sys.ReadFile(s.tlsPath(name))
	if err != nil {
		return nil, err
	}
	cs, err := pemCerts(b)
	if err == nil && len(cs) == 0 {
		err = fmt.Errorf("%s: no certificate", name)
	}
	return cs, err
}

// anchorPEM is the certificate devices must trust for what is in use now: keelAuth's CA, or
// the root of the office's chain.
func (s *Server) anchorPEM() ([]byte, error) {
	if s.officeActive() {
		if b, err := s.Sys.ReadFile(s.tlsPath(officeAnchorFile)); err == nil {
			return b, nil
		}
	}
	return s.caPEM()
}

func (s *Server) certsOut() (map[string]any, error) {
	out := map[string]any{"in_use": "own", "fingerprint": s.Fingerprint()}
	if cs, err := s.readCerts(caCertFile); err == nil {
		out["own_ca"] = s.certInfo(cs[0])
	}
	if s.officeActive() {
		out["in_use"] = "office"
		if b, err := s.Sys.ReadFile(s.tlsPath(officeMetaFile)); err == nil {
			out["office_uploaded"] = strings.TrimSpace(string(b))
		}
	}
	if b, err := s.anchorPEM(); err == nil {
		if cs, err := pemCerts(b); err == nil && len(cs) > 0 {
			out["anchor"] = s.certInfo(cs[0])
		}
	}
	if cs, err := s.readCerts(useServerChain); err == nil {
		out["server"] = s.certInfo(cs[0])
	}
	if cs, err := s.readCerts(useRadiusChain); err == nil {
		out["radius"] = s.certInfo(cs[0])
	}
	return out, nil
}

func (s *Server) getCerts(r *http.Request) (any, error) { return s.certsOut() }

// certAlerts: the office's certificate near its end or past it (keelAuth's own renew
// themselves).
func (s *Server) certAlerts() []Alert {
	if !s.officeActive() {
		return nil
	}
	cs, err := s.readCerts(useServerChain)
	if err != nil {
		return []Alert{{"cert_unreadable", "error", "certificate", "the office's certificate cannot be read: " + err.Error()}}
	}
	left := cs[0].NotAfter.Sub(s.now())
	end := cs[0].NotAfter.UTC().Format("2006-01-02")
	switch {
	case left <= 0:
		return []Alert{{"cert_expired", "error", "certificate", "the office's certificate ended on " + end +
			": devices that check it refuse LDAPS, single sign-on and Wi-Fi. Upload a new one (Settings → Certificates) or go back to keelAuth's own"}}
	case left < certWarnBefore:
		return []Alert{{"cert_expiring", "warning", "certificate", fmt.Sprintf("the office's certificate ends on %s (in %d days): upload a new one (Settings → Certificates)", end, int(left.Hours()/24))}}
	}
	return nil
}

// ---- downloads

// getCA is the certificate devices trust (the one in use; ?which=own: keelAuth's own CA) as
// PEM (.crt), or DER (?format=der, .cer: what Windows and Android take best).
func (s *Server) getCA(w http.ResponseWriter, r *http.Request) {
	var b []byte
	var err error
	name := "keelauth-ca"
	if r.URL.Query().Get("which") == "own" || !s.officeActive() {
		b, err = s.caPEM()
	} else {
		b, err = s.anchorPEM()
		name = "office-ca"
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	if r.URL.Query().Get("format") == "der" {
		p, _ := pem.Decode(b)
		if p == nil {
			writeErr(w, errors.New("the CA certificate is not PEM"))
			return
		}
		w.Header().Set("Content-Type", "application/pkix-cert")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.cer"`)
		w.Write(p.Bytes)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.crt"`)
	w.Write(b)
}

// getMobileconfig is an Apple configuration profile (iPhone, iPad, Mac) with the CA in use as a
// trusted root. Unsigned: the device shows it as "not verified"; after installing, iOS also
// wants it turned on in Settings → General → About → Certificate Trust Settings.
func (s *Server) getMobileconfig(w http.ResponseWriter, r *http.Request) {
	b, err := s.anchorPEM()
	if err != nil {
		writeErr(w, err)
		return
	}
	cs, err := pemCerts(b)
	if err != nil || len(cs) == 0 {
		writeErr(w, errors.New("the CA certificate is not PEM"))
		return
	}
	w.Header().Set("Content-Type", "application/x-apple-aspen-config")
	w.Header().Set("Content-Disposition", `attachment; filename="keelauth-ca.mobileconfig"`)
	w.Write(Mobileconfig(cs[0], s.State().Domain))
}

// Mobileconfig makes the profile: one com.apple.security.root payload. Its UUIDs come from the
// certificate, so the same CA gives the same profile (installing it again replaces it).
func Mobileconfig(ca *x509.Certificate, domain string) []byte {
	sum := sha256.Sum256(ca.Raw)
	uuid := func(salt byte) string {
		h := sha256.Sum256(append([]byte{salt}, sum[:]...))
		x := hex.EncodeToString(h[:16])
		return strings.ToUpper(x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32])
	}
	esc := func(v string) string {
		var b bytes.Buffer
		for _, r := range v {
			switch r {
			case '&':
				b.WriteString("&amp;")
			case '<':
				b.WriteString("&lt;")
			case '>':
				b.WriteString("&gt;")
			default:
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	der := base64.StdEncoding.EncodeToString(ca.Raw)
	var wrapped strings.Builder
	for i := 0; i < len(der); i += 64 {
		j := min(i+64, len(der))
		wrapped.WriteString("\t\t\t" + der[i:j] + "\n")
	}
	cn := ca.Subject.CommonName
	id := "lan.keelauth." + strings.NewReplacer(".", "-", " ", "-").Replace(domain)
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>keelauth-ca.cer</string>
			<key>PayloadContent</key>
			<data>
` + wrapped.String() + `			</data>
			<key>PayloadDescription</key>
			<string>Trusts ` + esc(cn) + ` for ` + esc(domain) + ` (LDAPS, single sign-on, Wi-Fi)</string>
			<key>PayloadDisplayName</key>
			<string>` + esc(cn) + `</string>
			<key>PayloadIdentifier</key>
			<string>` + esc(id) + `.ca</string>
			<key>PayloadType</key>
			<string>com.apple.security.root</string>
			<key>PayloadUUID</key>
			<string>` + uuid(1) + `</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>
	</array>
	<key>PayloadDescription</key>
	<string>The certificate authority of keelAuth ` + esc(domain) + `</string>
	<key>PayloadDisplayName</key>
	<string>keelAuth ` + esc(domain) + `</string>
	<key>PayloadIdentifier</key>
	<string>` + esc(id) + `</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>` + uuid(0) + `</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`)
}

// ---- the office's own certificate

// OfficeCert is an uploaded certificate after the checks.
type OfficeCert struct {
	Chain    []*x509.Certificate // leaf first, the anchor last
	Key      crypto.Signer
	KeyPEM   []byte
	Warnings []string
}

// parseKey reads a private key in PEM: PKCS#8, PKCS#1 (RSA) or SEC 1 (EC).
func parseKey(b []byte) (crypto.Signer, error) {
	for {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p == nil {
			return nil, errors.New("no private key (PEM: BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY or BEGIN EC PRIVATE KEY)")
		}
		if p.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(p.Headers["Proc-Type"], "ENCRYPTED") {
			return nil, errors.New("the key is protected by a passphrase: export it without one (openssl pkey -in KEY -out plain.key)")
		}
		var k any
		var err error
		switch p.Type {
		case "PRIVATE KEY":
			k, err = x509.ParsePKCS8PrivateKey(p.Bytes)
		case "RSA PRIVATE KEY":
			k, err = x509.ParsePKCS1PrivateKey(p.Bytes)
		case "EC PRIVATE KEY":
			k, err = x509.ParseECPrivateKey(p.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("the key cannot be read: %v", err)
		}
		sk, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("the key cannot sign")
		}
		switch k := sk.(type) {
		case *rsa.PrivateKey:
			// Kanidm refuses to start with less ("Private Key does not meet cryptographic
			// minimum standards: TLS RSA key is less than 2048 bits", seen in QEMU)
			if k.N.BitLen() < 2048 {
				return nil, fmt.Errorf("an RSA key of %d bits: Kanidm needs at least 2048", k.N.BitLen())
			}
		case *ecdsa.PrivateKey:
		default:
			return nil, errors.New("only RSA and ECDSA keys (Kanidm and FreeRADIUS take no other)")
		}
		return sk, nil
	}
}

func samePublic(a, b any) bool {
	type eq interface{ Equal(crypto.PublicKey) bool }
	x, ok := a.(eq)
	return ok && x.Equal(b)
}

// CheckOffice checks an uploaded certificate for the domain: it parses, its key belongs to it,
// it names the domain, it is valid now, it is for servers, and its chain leads to a root
// (one in the upload, or one the system trusts: a public CA). Roots may be nil (the system's).
func CheckOffice(certPEM, keyPEM []byte, domain string, now time.Time, roots *x509.CertPool) (*OfficeCert, error) {
	if len(keyPEM) == 0 {
		keyPEM = certPEM // one file with both
	}
	certs, err := pemCerts(certPEM)
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, errors.New("no certificate (PEM: BEGIN CERTIFICATE)")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	var leaf *x509.Certificate
	inter := x509.NewCertPool()
	own := x509.NewCertPool()
	nown := 0
	for _, c := range certs {
		if samePublic(c.PublicKey, key.Public()) {
			leaf = c
			continue
		}
		if bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			own.AddCert(c) // a root in the upload: the office's own CA
			nown++
		} else {
			inter.AddCert(c)
		}
	}
	if leaf == nil {
		return nil, errors.New("the key belongs to none of the certificates")
	}
	if leaf.IsCA {
		return nil, errors.New("the certificate for the key is a CA certificate, not a server's")
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate is valid only from %s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate ended on %s", leaf.NotAfter.UTC().Format("2006-01-02"))
	}
	if err := leaf.VerifyHostname(domain); err != nil {
		return nil, fmt.Errorf("the certificate is not for %s (keelAuth's domain): it names %s", domain, strings.Join(leaf.DNSNames, ", "))
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasEKU(leaf, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("the certificate is not for TLS servers (its extended key usage lacks serverAuth; Windows also refuses it for Wi-Fi)")
	}
	opts := x509.VerifyOptions{DNSName: domain, Intermediates: inter, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	var chains [][]*x509.Certificate
	if nown > 0 {
		opts.Roots = own
		chains, err = leaf.Verify(opts)
	}
	if len(chains) == 0 {
		opts.Roots = roots // nil: the system's
		if chains, err = leaf.Verify(opts); err != nil {
			return nil, fmt.Errorf("the chain does not lead to a trusted root (%v): add the intermediate and root certificates to the certificate file", err)
		}
	}
	oc := &OfficeCert{Chain: chains[0], Key: key}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	oc.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if left := leaf.NotAfter.Sub(now); left < certWarnBefore {
		oc.Warnings = append(oc.Warnings, fmt.Sprintf("it ends in %d days", int(left.Hours()/24)))
	}
	if _, ok := key.(*ecdsa.PrivateKey); ok {
		oc.Warnings = append(oc.Warnings, "an ECDSA key: old Wi-Fi clients (Windows 7, old Android) may refuse PEAP with it")
	}
	if len(chains[0]) == 1 {
		oc.Warnings = append(oc.Warnings, "a self-signed certificate: devices must trust this certificate itself")
	}
	return oc, nil
}

func hasEKU(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, x := range c.ExtKeyUsage {
		if x == u || x == x509.ExtKeyUsageAny {
			return true
		}
	}
	return false
}

// SystemRoots is the pool CheckOffice uses for public CAs (nil = the system's; tests set one).
var SystemRoots *x509.CertPool

func (s *Server) postOfficeCert(r *http.Request) (any, error) {
	var req struct {
		Cert string `json:"cert"`
		Key  string `json:"key"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if len(req.Cert) > officeMaxPEMBytes || len(req.Key) > officeMaxPEMBytes {
		return nil, bad("too big for a certificate")
	}
	st := s.State()
	oc, err := CheckOffice([]byte(req.Cert), []byte(req.Key), st.Domain, s.now(), SystemRoots)
	if err != nil {
		return nil, coded(http.StatusBadRequest, "bad_certificate", "%v", err)
	}
	var chain []byte
	for _, c := range oc.Chain {
		chain = append(chain, certPEM(c.Raw)...)
	}
	anchor := certPEM(oc.Chain[len(oc.Chain)-1].Raw)
	s.certMu.Lock()
	defer s.certMu.Unlock()
	prev := s.officeFiles()
	for _, f := range []struct {
		name string
		b    []byte
		perm uint32
	}{{officeKeyFile, oc.KeyPEM, 0o600}, {officeAnchorFile, anchor, 0o644}, {officeMetaFile, []byte(s.now().Format(time.RFC3339) + "\n"), 0o644},
		{officeChainFile, chain, 0o644}} { // the chain last: it switches
		if err := s.Sys.WriteFile(s.tlsPath(f.name), f.b, osMode(f.perm)); err != nil {
			s.restoreOffice(prev)
			return nil, err
		}
	}
	if err := s.switchCerts(); err != nil {
		s.Log.Printf("tls: the office's certificate did not work, back to what was in use: %v", err)
		s.restoreOffice(prev)
		if err2 := s.switchCerts(); err2 != nil {
			s.Log.Printf("tls: going back: %v", err2)
		}
		return nil, coded(http.StatusBadRequest, "certificate_refused", "the services did not start with it (%v); keelAuth went back to the certificate it had", err)
	}
	s.Log.Printf("tls: the office's certificate is in use (%s, until %s)", oc.Chain[0].Subject, oc.Chain[0].NotAfter.UTC().Format("2006-01-02"))
	out, _ := s.certsOut()
	out["warnings"] = oc.Warnings
	return out, nil
}

func (s *Server) deleteOfficeCert(r *http.Request) (any, error) {
	s.certMu.Lock()
	defer s.certMu.Unlock()
	if !s.officeActive() {
		return nil, notFound("keelAuth uses its own certificates already")
	}
	prev := s.officeFiles()
	for _, f := range []string{officeChainFile, officeKeyFile, officeAnchorFile, officeMetaFile} {
		s.Sys.Remove(s.tlsPath(f))
	}
	if err := s.switchCerts(); err != nil {
		s.restoreOffice(prev)
		s.switchCerts()
		return nil, err
	}
	s.Log.Printf("tls: back to keelAuth's own certificates")
	return s.certsOut()
}

// officeFiles / restoreOffice: what was there before a change (nil entries: none).
func (s *Server) officeFiles() map[string][]byte {
	m := map[string][]byte{}
	for _, f := range []string{officeChainFile, officeKeyFile, officeAnchorFile, officeMetaFile} {
		if b, err := s.Sys.ReadFile(s.tlsPath(f)); err == nil {
			m[f] = b
		} else {
			m[f] = nil
		}
	}
	return m
}

func (s *Server) restoreOffice(m map[string][]byte) {
	for _, f := range []string{officeKeyFile, officeAnchorFile, officeMetaFile, officeChainFile} {
		if m[f] == nil {
			s.Sys.Remove(s.tlsPath(f))
		} else {
			s.Sys.WriteFile(s.tlsPath(f), m[f], osMode(0o600))
		}
	}
	if m[officeKeyFile] != nil {
		s.Sys.Run("", "chmod", "0600", s.tlsPath(officeKeyFile))
	}
	for _, f := range []string{officeChainFile, officeAnchorFile, officeMetaFile} {
		if m[f] != nil {
			s.Sys.Run("", "chmod", "0644", s.tlsPath(f))
		}
	}
}

// switchCerts writes the use files and restarts what reads them; it waits until both
// services are up again and says why not.
func (s *Server) switchCerts() error {
	ch, err := s.applyCerts()
	if err != nil {
		return err
	}
	if !s.Real {
		return nil
	}
	if ch.Server {
		if _, err := s.Sys.Run("", "service", "kanidmd", "onerestart"); err != nil {
			return fmt.Errorf("kanidmd: %v", err)
		}
	}
	if ch.Radius {
		if _, err := s.Sys.Run("", "service", "radiusd", "onerestart"); err != nil {
			return fmt.Errorf("radiusd: %v", err)
		}
	}
	svc := s.waitServices()
	for _, n := range []string{"kanidmd", "radiusd"} {
		if svc[n] != nil {
			return fmt.Errorf("%s: %v", n, svc[n])
		}
	}
	// Kanidm answers keelauthd again (its REST is on the same certificate)
	for i := 0; i < 15; i++ {
		if err = s.Eng.Ready(); err == nil {
			return nil
		}
		s.sleep(2 * time.Second)
	}
	return fmt.Errorf("kanidmd does not answer: %v", err)
}
