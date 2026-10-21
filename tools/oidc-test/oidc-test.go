// oidc-test: the smallest OpenID Connect web application, for checking a keelAuth SSO
// registration end to end the way any other application (GitLab, Redmine, …) uses it: the
// browser goes to keelAuth's own login page at https://<domain>:8443, the application talks to
// Kanidm by its name (DNS, or -resolve) and checks its certificate with keelAuth's CA.
//
//	go run tools/oidc-test/oidc-test.go -discovery https://auth.office.lan:8443/oauth2/openid/oidctest/.well-known/openid-configuration \
//	   -client oidctest -secret … -ca ca.crt [-resolve auth.office.lan=192.0.2.10] [-listen 127.0.0.1:9443]
//
// It serves https://<listen>/ (a "Log in" link) and /cb (the redirect URL to register in keelAuth),
// does the code flow with PKCE S256, state and nonce, checks the ID token (ES256 or RS256 against
// the JWKS, iss, aud, exp, nonce) and shows its claims. Standard library only.
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	discovery = flag.String("discovery", "", "the discovery URL keelAuth shows for the application")
	clientID  = flag.String("client", "", "client id")
	secret    = flag.String("secret", "", "client secret")
	caFile    = flag.String("ca", "", "keelAuth's CA (PEM; keelAuth's page, LDAP tab)")
	resolve   = flag.String("resolve", "", "host=ip: reach keelAuth's domain at this address (no DNS entry)")
	listen    = flag.String("listen", "127.0.0.1:9443", "where this application listens (HTTPS, self-signed)")
)

type provider struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
}

var (
	hc      *http.Client
	prov    provider
	mu      sync.Mutex
	pending = map[string][2]string{} // state -> nonce, verifier
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rnd() string {
	b := make([]byte, 24)
	rand.Read(b)
	return b64(b)
}

func getJSON(u string, v any) error {
	res, err := hc.Get(u)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("%s: %s", u, res.Status)
	}
	return json.NewDecoder(res.Body).Decode(v)
}

func redirectURL() string { return "https://" + *listen + "/cb" }

func login(w http.ResponseWriter, r *http.Request) {
	state, nonce, ver := rnd(), rnd(), rnd()
	h := sha256.Sum256([]byte(ver))
	mu.Lock()
	pending[state] = [2]string{nonce, ver}
	mu.Unlock()
	q := url.Values{"response_type": {"code"}, "client_id": {*clientID}, "redirect_uri": {redirectURL()},
		"scope": {"openid profile email groups"}, "state": {state}, "nonce": {nonce},
		"code_challenge": {b64(h[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, prov.AuthURL+"?"+q.Encode(), http.StatusSeeOther)
}

func callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	mu.Lock()
	p, ok := pending[q.Get("state")]
	delete(pending, q.Get("state"))
	mu.Unlock()
	if e := q.Get("error"); e != "" || !ok {
		http.Error(w, "refused: "+e+" "+q.Get("error_description")+fmt.Sprintf(" (state known: %v)", ok), 403)
		return
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {redirectURL()}, "code_verifier": {p[1]}}
	req, _ := http.NewRequest("POST", prov.TokenURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(*clientID), url.QueryEscape(*secret))
	res, err := hc.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 502)
		return
	}
	defer res.Body.Close()
	var tok struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	json.NewDecoder(res.Body).Decode(&tok)
	if res.StatusCode != 200 || tok.IDToken == "" {
		http.Error(w, fmt.Sprintf("token request: %s %s", res.Status, tok.Error), 502)
		return
	}
	claims, err := verify(tok.IDToken, p[0])
	if err != nil {
		http.Error(w, "ID token: "+err.Error(), 403)
		return
	}
	b, _ := json.MarshalIndent(claims, "", "  ")
	log.Printf("logged in: %s groups %v", claims["preferred_username"], claims["groups"])
	fmt.Fprintf(w, "<!doctype html><title>oidc-test</title><h1>Logged in as %s</h1><p>ID token checked (signature, iss, aud, exp, nonce).</p><pre id=claims>%s</pre>",
		html.EscapeString(fmt.Sprint(claims["preferred_username"])), html.EscapeString(string(b)))
}

func verify(raw, nonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWS")
	}
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var hdr struct{ Alg, Kid string }
	json.Unmarshal(hb, &hdr)
	var set struct {
		Keys []struct{ Kty, Kid, Crv, X, Y, N, E string } `json:"keys"`
	}
	if err := getJSON(prov.JWKSURL, &set); err != nil {
		return nil, err
	}
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	okSig := false
	for _, k := range set.Keys {
		if hdr.Kid != "" && k.Kid != hdr.Kid {
			continue
		}
		switch {
		case hdr.Alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256" && len(sig) == 64:
			x, _ := base64.RawURLEncoding.DecodeString(k.X)
			y, _ := base64.RawURLEncoding.DecodeString(k.Y)
			pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...))
			okSig = err == nil && ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
		case hdr.Alg == "RS256" && k.Kty == "RSA":
			n, _ := base64.RawURLEncoding.DecodeString(k.N)
			e, _ := base64.RawURLEncoding.DecodeString(k.E)
			pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
			okSig = rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
		}
		if okSig {
			break
		}
	}
	if !okSig {
		return nil, fmt.Errorf("signature (%s, kid %s) not verified", hdr.Alg, hdr.Kid)
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var c map[string]any
	if err := json.Unmarshal(pb, &c); err != nil {
		return nil, err
	}
	aud := fmt.Sprint(c["aud"])
	exp, _ := c["exp"].(float64)
	switch {
	case c["iss"] != prov.Issuer:
		return nil, fmt.Errorf("iss %v", c["iss"])
	case aud != *clientID && !strings.Contains(aud, *clientID):
		return nil, fmt.Errorf("aud %v", c["aud"])
	case time.Now().After(time.Unix(int64(exp), 0).Add(time.Minute)):
		return nil, errors.New("expired")
	case c["nonce"] != nonce:
		return nil, errors.New("nonce")
	}
	return c, nil
}

func selfCert() tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	h, _, _ := net.SplitHostPort(*listen)
	t := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: h}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IPAddresses: []net.IP{net.ParseIP(h)}, DNSNames: []string{h}}
	der, _ := x509.CreateCertificate(rand.Reader, t, t, &k.PublicKey, k)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func main() {
	flag.Parse()
	if *discovery == "" || *clientID == "" || *secret == "" {
		flag.Usage()
		os.Exit(2)
	}
	tlsc := &tls.Config{}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			log.Fatal(err)
		}
		tlsc.RootCAs = x509.NewCertPool()
		tlsc.RootCAs.AppendCertsFromPEM(pem)
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{TLSClientConfig: tlsc, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if host, port, _ := net.SplitHostPort(addr); *resolve != "" {
			if name, ip, _ := strings.Cut(*resolve, "="); strings.EqualFold(host, name) {
				addr = net.JoinHostPort(ip, port)
			}
		}
		return d.DialContext(ctx, network, addr)
	}}
	hc = &http.Client{Transport: tr, Timeout: 15 * time.Second}
	if err := getJSON(*discovery, &prov); err != nil {
		log.Fatalf("discovery: %v", err)
	}
	log.Printf("issuer %s; register the redirect URL %s", prov.Issuer, redirectURL())
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<!doctype html><title>oidc-test</title><h1>oidc-test</h1><p><a id=login href="/login">Log in with keelAuth</a></p>`)
	})
	mux.HandleFunc("GET /login", login)
	mux.HandleFunc("GET /cb", callback)
	srv := &http.Server{Addr: *listen, Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{selfCert()}}}
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
