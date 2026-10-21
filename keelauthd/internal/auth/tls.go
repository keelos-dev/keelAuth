package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"slices"
	"time"
)

// keelAuth's certificates (docs/02 section 2 and 7.6): its own CA and two certificates signed by
// it. Devices install the CA once (GET /v1/ca) and then trust all of them. Files in <data>/tls.
//
//   - the CA: RSA 3072, 20 years. RSA because old Wi-Fi clients (Windows 7, older Android,
//     printers and phones of that age) do not all check ECDSA signatures in a chain they validate
//     for PEAP; every client checks RSA. A CA made earlier with another key stays as it is (devices
//     have installed it).
//   - the server certificate (Kanidm's HTTPS and LDAPS, keelauthd's web page): ECDSA P-256. Its
//     names are the domain, the host name and localhost, its addresses 127.0.0.1 and the internal
//     link's (from the seed). **No LAN address**: keel-mcp pins this certificate's fingerprint, so
//     it must not change when DHCP gives a new address. Made again only when the domain changes,
//     it is not signed by the CA, or it ends within 30 days.
//   - the RADIUS certificate (FreeRADIUS's EAP: PEAP, TTLS): RSA 2048, names the domain and the
//     host name. Made again on the same conditions.

const (
	caCertFile      = "ca.crt"
	caKeyFile       = "ca.key"
	serverCertFile  = "server.crt"
	serverKeyFile   = "server.key"
	chainFile       = "chain.pem"
	radiusCertFile  = "radius.crt"
	radiusKeyFile   = "radius.key"
	radiusChainFile = "radius-chain.pem"
	renewBefore     = 30 * 24 * time.Hour
)

func (s *Server) tlsDir() string { return filepath.Join(s.Data, "tls") }

// keyKind is the kind of key a certificate gets.
type keyKind int

const (
	keyECDSA keyKind = iota
	keyRSA2048
	keyRSA3072
)

func newKey(kind keyKind) (crypto.Signer, []byte, error) {
	var k crypto.Signer
	var err error
	switch kind {
	case keyRSA2048:
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case keyRSA3072:
		k, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, nil, err
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	return n
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// readPair reads a PEM certificate and its key.
func (s *Server) readPair(certFile, keyFile string) (*x509.Certificate, crypto.Signer, error) {
	cb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), certFile))
	if err != nil {
		return nil, nil, err
	}
	kb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), keyFile))
	if err != nil {
		return nil, nil, err
	}
	cp, _ := pem.Decode(cb)
	kp, _ := pem.Decode(kb)
	if cp == nil || kp == nil {
		return nil, nil, errors.New("not PEM")
	}
	c, err := x509.ParseCertificate(cp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	k, err := x509.ParsePKCS8PrivateKey(kp.Bytes)
	if err != nil {
		return nil, nil, err
	}
	sk, ok := k.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("not a signing key")
	}
	return c, sk, nil
}

// TLSChanged says which certificates EnsureTLS made new (their users must restart).
type TLSChanged struct{ Server, Radius bool }

// EnsureTLS makes the CA when there is none, and the server and RADIUS certificates when they
// are missing, not signed by the CA, lack the domain, or end within 30 days (see the top of
// this file). internalIP is the internal link's address ("" without one); it goes into a new
// server certificate but a change of it alone makes none.
func (s *Server) EnsureTLS(domain, internalIP string) (TLSChanged, error) {
	var ch TLSChanged
	dir := s.tlsDir()
	ca, caKey, err := s.readPair(caCertFile, caKeyFile)
	if err != nil {
		k, kpem, err := newKey(keyRSA3072)
		if err != nil {
			return ch, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: serial(), Subject: pkix.Name{CommonName: "keelAuth CA " + domain, Organization: []string{"keelAuth"}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(20, 0, 0),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
		if err != nil {
			return ch, err
		}
		if err := s.Sys.WriteFile(filepath.Join(dir, caKeyFile), kpem, 0o600); err != nil {
			return ch, err
		}
		if err := s.Sys.WriteFile(filepath.Join(dir, caCertFile), certPEM(der), 0o644); err != nil {
			return ch, err
		}
		ca, _ = x509.ParseCertificate(der)
		caKey = k
		s.Log.Printf("tls: made keelAuth's CA (RSA 3072)")
	}
	names := []string{domain, s.hostname(), "localhost"}
	ips := []net.IP{net.ParseIP("127.0.0.1")}
	if ip := net.ParseIP(internalIP); ip != nil {
		ips = append(ips, ip)
	}
	// the IP origin (docs/02 section 7.14): the LAN address is a SAN of the server certificate
	var lan net.IP
	if mode, a, _, _ := s.OriginInfo(); mode == "ip" {
		lan = net.ParseIP(a)
		ips = append(ips, lan)
	}
	if ch.Server, err = s.ensureLeaf(ca, caKey, serverCertFile, serverKeyFile, chainFile, keyECDSA, domain, names, ips, lan); err != nil {
		return ch, err
	}
	if ch.Radius, err = s.ensureLeaf(ca, caKey, radiusCertFile, radiusKeyFile, radiusChainFile, keyRSA2048, domain,
		[]string{domain, s.hostname()}, nil, nil); err != nil {
		return ch, err
	}
	// what the services read (the own ones, or the office's: certs.go)
	use, err := s.applyCerts()
	if err != nil {
		return ch, err
	}
	ch.Server, ch.Radius = ch.Server || use.Server, ch.Radius || use.Radius
	return ch, nil
}

// lanSANOK: the certificate has the LAN address as a SAN exactly when lan is set; without lan it
// has no address but loopback and the link-local internal one (the IP origin was switched off or
// the address changed: a new certificate).
func lanSANOK(c *x509.Certificate, lan net.IP) bool {
	have := false
	for _, ip := range c.IPAddresses {
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if lan == nil || !ip.Equal(lan) {
			return false
		}
		have = true
	}
	return lan == nil || have
}

// ensureLeaf keeps a certificate that is signed by the CA, names the domain and lasts more
// than 30 days; else it makes a new one. It reports whether it did.
func (s *Server) ensureLeaf(ca *x509.Certificate, caKey crypto.Signer, certFile, keyFile, chain string, kind keyKind,
	domain string, names []string, ips []net.IP, lan net.IP) (bool, error) {
	dir := s.tlsDir()
	if c, _, err := s.readPair(certFile, keyFile); err == nil && time.Until(c.NotAfter) > renewBefore &&
		slices.Contains(c.DNSNames, domain) && lanSANOK(c, lan) && c.CheckSignatureFrom(ca) == nil {
		return false, nil
	}
	k, kpem, err := newKey(kind)
	if err != nil {
		return false, err
	}
	pub, _ := x509.MarshalPKIXPublicKey(k.Public())
	ski := sha256.Sum256(pub)
	ku := x509.KeyUsageDigitalSignature
	if kind != keyECDSA {
		ku |= x509.KeyUsageKeyEncipherment // RSA key exchange (old TLS clients)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial(), Subject: pkix.Name{CommonName: domain, Organization: []string{"keelAuth"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0),
		KeyUsage: ku, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, DNSNames: names, IPAddresses: ips, SubjectKeyId: ski[:20],
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, k.Public(), caKey)
	if err != nil {
		return false, err
	}
	if err := s.Sys.WriteFile(filepath.Join(dir, keyFile), kpem, 0o640); err != nil {
		return false, err
	}
	if err := s.Sys.WriteFile(filepath.Join(dir, certFile), certPEM(der), 0o644); err != nil {
		return false, err
	}
	caPEM, _ := s.Sys.ReadFile(filepath.Join(dir, caCertFile))
	if err := s.Sys.WriteFile(filepath.Join(dir, chain), append(certPEM(der), caPEM...), 0o644); err != nil {
		return false, err
	}
	s.Log.Printf("tls: new %s for %v %v", certFile, names, ips)
	return true, nil
}

// serverCert is the web page's certificate (re-read for every handshake, so a new one is used
// without a restart).
func (s *Server) serverCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cf, kf := useServerChain, useServerKey // the one in use (certs.go)
	if _, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), cf)); err != nil {
		cf, kf = chainFile, serverKeyFile
	}
	cb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), cf))
	if err != nil {
		return nil, err
	}
	kb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), kf))
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Fingerprint is the SHA-256 of the web page's certificate, AB:CD:… (keel-mcp --fingerprint).
func (s *Server) Fingerprint() string {
	c, err := s.serverCert(nil)
	if err != nil || len(c.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(c.Certificate[0])
	return FormatFingerprint(sum[:])
}

// caPEM is the CA certificate.
func (s *Server) caPEM() ([]byte, error) {
	b, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), caCertFile))
	if err != nil {
		return nil, fmt.Errorf("no CA yet: %v", err)
	}
	return b, nil
}
