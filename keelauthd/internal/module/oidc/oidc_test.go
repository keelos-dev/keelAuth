package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"keelauth/internal/engine"
)

type fakeDir struct{ origin string }

func (d fakeDir) Origin() string        { return d.origin }
func (fakeDir) Domain() string          { return "auth.office.lan" }
func (fakeDir) Brand() (string, string) { return "ACME", "" }
func (fakeDir) CheckPassword(n, p string) bool {
	return n == "alice" && p == "alice-pw" || n == "bob" && p == "bob-pw"
}
func (fakeDir) CheckSecret(id, sec string) bool {
	return id == "keel-host1" && sec == "s3cret" || id == "legacy" && sec == "old"
}
func (fakeDir) Clients() []engine.OAuth2 {
	return []engine.OAuth2{
		{Name: "keel-host1", DisplayName: "keelOS host1", LandingURL: "https://host1/", RedirectURLs: []string{"https://host1/sso/callback"}, ScopeMaps: map[string][]string{"keel-admins": {"openid", "profile", "email", "groups"}}, PKCE: true, ShortName: true},
		{Name: "legacy", DisplayName: "Legacy", LandingURL: "https://legacy/", RedirectURLs: []string{"https://legacy/cb"}, ScopeMaps: map[string][]string{engine.AllPersons: {"openid", "email"}}, PKCE: false, RS256: true},
	}
}
func (d fakeDir) Client(id string) (*engine.OAuth2, bool) {
	for _, c := range d.Clients() {
		if c.Name == id {
			return &c, true
		}
	}
	return nil, false
}
func (fakeDir) Allowed(n, c string) bool { return !(n == "bob" && c == "keel-host1") || true }

func (fakeDir) Person(n string) (Person, bool) {
	switch n {
	case "alice":
		return Person{Name: "alice", DisplayName: "Alice A", Mail: "alice@example.com", UUID: "u-alice", Groups: []string{"keel-admins", "staff"}}, true
	case "bob":
		return Person{Name: "bob", UUID: "u-bob", Groups: []string{"staff"}}, true
	}
	return Person{}, false
}

func newProvider(t *testing.T) (*Server, *httptest.Server, *http.Client) {
	t.Helper()
	var s *Server
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.ServeHTTP(w, r) }))
	s, _ = New(fakeDir{ts.URL}, t.TempDir(), nil)
	jar, _ := cookiejar.New(nil)
	cl := ts.Client()
	cl.Jar = jar
	cl.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	t.Cleanup(ts.Close)
	return s, ts, cl
}

func get(t *testing.T, cl *http.Client, u string) (*http.Response, string) {
	t.Helper()
	r, err := cl.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r, string(b)
}

func post(t *testing.T, cl *http.Client, u string, form url.Values, basic [2]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic[0] != "" {
		req.SetBasicAuth(basic[0], basic[1])
	}
	r, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(r.Body)
	r.Body.Close()
	return r, string(b)
}

func b64d(s string) []byte { b, _ := base64.RawURLEncoding.DecodeString(s); return b }

func TestCodeFlowWithPKCE(t *testing.T) {
	_, ts, cl := newProvider(t)
	// discovery
	r, body := get(t, cl, ts.URL+"/oauth2/openid/keel-host1/.well-known/openid-configuration")
	var disc map[string]any
	json.Unmarshal([]byte(body), &disc)
	if r.StatusCode != 200 || disc["issuer"] != ts.URL+"/oauth2/openid/keel-host1" || disc["authorization_endpoint"] != ts.URL+"/ui/oauth2" || disc["token_endpoint"] != ts.URL+"/oauth2/token" {
		t.Fatalf("discovery: %d %s", r.StatusCode, body)
	}
	// authorize without a session: to the login page, back after it
	verifier := "a-verifier-that-is-long-enough-for-pkce-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {"keel-host1"}, "redirect_uri": {"https://host1/sso/callback"}, "scope": {"openid profile email groups"},
		"state": {"st1"}, "nonce": {"n1"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	authURL := ts.URL + "/ui/oauth2?" + q.Encode()
	r, _ = get(t, cl, authURL)
	loc := r.Header.Get("Location")
	if r.StatusCode != 302 || !strings.HasPrefix(loc, "/ui/login?return=") {
		t.Fatalf("authorize without session: %d %s", r.StatusCode, loc)
	}
	r, body = get(t, cl, ts.URL+loc)
	if r.StatusCode != 200 || !strings.Contains(body, "Sign in to ACME") || strings.Contains(body, "<script") {
		t.Fatalf("login page: %d %s", r.StatusCode, body[:120])
	}
	ret, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/ui/login?return="))
	r, body = post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"alice"}, "password": {"wrong"}, "return": {ret}}, [2]string{})
	if r.StatusCode != 200 || !strings.Contains(body, "wrong user name or password") {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	r, _ = post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"Alice@auth.office.lan"}, "password": {"alice-pw"}, "return": {ret}}, [2]string{})
	if r.StatusCode != 303 || r.Header.Get("Location") != ret {
		t.Fatalf("login: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	// now the code comes
	r, _ = get(t, cl, authURL)
	loc = r.Header.Get("Location")
	if r.StatusCode != 302 || !strings.HasPrefix(loc, "https://host1/sso/callback?") {
		t.Fatalf("authorize: %d %s", r.StatusCode, loc)
	}
	cb, _ := url.Parse(loc)
	code := cb.Query().Get("code")
	if code == "" || cb.Query().Get("state") != "st1" {
		t.Fatalf("callback: %s", loc)
	}
	// the token endpoint: wrong secret, wrong verifier, then right
	r, _ = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://host1/sso/callback"}, "code_verifier": {verifier}}, [2]string{"keel-host1", "nope"})
	if r.StatusCode != 401 {
		t.Fatalf("wrong secret: %d", r.StatusCode)
	}
	r, body = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://host1/sso/callback"}, "code_verifier": {"other"}}, [2]string{"keel-host1", "s3cret"})
	if r.StatusCode != 400 || !strings.Contains(body, "PKCE") {
		t.Fatalf("wrong verifier: %d %s", r.StatusCode, body)
	}
	// the code was used up by the failed try: log in again for a new one
	r, _ = get(t, cl, authURL)
	cb, _ = url.Parse(r.Header.Get("Location"))
	code = cb.Query().Get("code")
	r, body = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://host1/sso/callback"}, "code_verifier": {verifier}}, [2]string{"keel-host1", "s3cret"})
	var tok map[string]any
	json.Unmarshal([]byte(body), &tok)
	if r.StatusCode != 200 || tok["token_type"] != "Bearer" || tok["id_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %s", r.StatusCode, body)
	}
	// the ID token: ES256 signature against the JWKS, the claims
	parts := strings.Split(tok["id_token"].(string), ".")
	var hdr map[string]string
	json.Unmarshal(b64d(parts[0]), &hdr)
	if hdr["alg"] != "ES256" || hdr["kid"] == "" {
		t.Fatalf("header: %v", hdr)
	}
	_, body = get(t, cl, ts.URL+"/oauth2/openid/keel-host1/public_key.jwk")
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	json.Unmarshal([]byte(body), &jwks)
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != hdr["kid"] || jwks.Keys[0]["kty"] != "EC" {
		t.Fatalf("jwks: %s", body)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(b64d(jwks.Keys[0]["x"])), Y: new(big.Int).SetBytes(b64d(jwks.Keys[0]["y"]))}
	sig := b64d(parts[2])
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("ID token signature does not verify")
	}
	var claims map[string]any
	json.Unmarshal(b64d(parts[1]), &claims)
	if claims["iss"] != ts.URL+"/oauth2/openid/keel-host1" || claims["aud"] != "keel-host1" || claims["sub"] != "u-alice" || claims["nonce"] != "n1" ||
		claims["preferred_username"] != "alice" || claims["name"] != "Alice A" || claims["email"] != "alice@example.com" {
		t.Fatalf("claims: %v", claims)
	}
	if gs, _ := claims["groups"].([]any); len(gs) != 2 || gs[0] != "keel-admins" {
		t.Fatalf("groups claim: %v", claims["groups"])
	}
	// userinfo and introspection
	req, _ := http.NewRequest("GET", ts.URL+"/oauth2/openid/keel-host1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok["access_token"].(string))
	resp, _ := cl.Do(req)
	b, _ := io.ReadAll(resp.Body)
	var ui map[string]any
	json.Unmarshal(b, &ui)
	if resp.StatusCode != 200 || ui["sub"] != "u-alice" || ui["email"] != "alice@example.com" {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, b)
	}
	_, body = post(t, cl, ts.URL+"/oauth2/token/introspect", url.Values{"token": {tok["access_token"].(string)}}, [2]string{"keel-host1", "s3cret"})
	var intro map[string]any
	json.Unmarshal([]byte(body), &intro)
	if intro["active"] != true || intro["username"] != "alice" || intro["client_id"] != "keel-host1" {
		t.Fatalf("introspect: %s", body)
	}
	// refresh: a new pair, the old refresh token gone
	rt := tok["refresh_token"].(string)
	r, body = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, [2]string{"keel-host1", "s3cret"})
	if r.StatusCode != 200 || !strings.Contains(body, "id_token") {
		t.Fatalf("refresh: %d %s", r.StatusCode, body)
	}
	if r, _ = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, [2]string{"keel-host1", "s3cret"}); r.StatusCode != 400 {
		t.Fatalf("refresh token reused: %d", r.StatusCode)
	}
	// the applications page lists what alice may use
	_, body = get(t, cl, ts.URL+"/ui/apps")
	if !strings.Contains(body, "keelOS host1") || !strings.Contains(body, "Legacy") {
		t.Fatalf("apps: %s", body)
	}
	// logout ends the session
	get(t, cl, ts.URL+"/ui/logout")
	if r, _ = get(t, cl, authURL); !strings.HasPrefix(r.Header.Get("Location"), "/ui/login") {
		t.Fatal("still logged in after logout")
	}
}

func TestAccessAndRS256(t *testing.T) {
	_, ts, cl := newProvider(t)
	post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"bob"}, "password": {"bob-pw"}, "return": {"/ui/apps"}}, [2]string{})
	// bob is in no group of keel-host1: no access
	q := url.Values{"response_type": {"code"}, "client_id": {"keel-host1"}, "redirect_uri": {"https://host1/sso/callback"}, "scope": {"openid"}, "code_challenge": {"x"}, "code_challenge_method": {"S256"}}
	r, body := get(t, cl, ts.URL+"/ui/oauth2?"+q.Encode())
	if r.StatusCode != 400 || !strings.Contains(body, "no access") {
		t.Fatalf("bob at keel-host1: %d", r.StatusCode)
	}
	// unknown redirect, missing PKCE for a PKCE client, unknown client
	q.Set("redirect_uri", "https://evil/")
	if r, _ = get(t, cl, ts.URL+"/ui/oauth2?"+q.Encode()); r.StatusCode != 400 {
		t.Fatalf("bad redirect: %d", r.StatusCode)
	}
	q.Set("redirect_uri", "https://host1/sso/callback")
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	if r, _ = get(t, cl, ts.URL+"/ui/oauth2?"+q.Encode()); r.StatusCode != 302 || !strings.Contains(r.Header.Get("Location"), "error=invalid_request") {
		t.Fatalf("no PKCE: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	// legacy: everyone, no PKCE, RS256
	q = url.Values{"response_type": {"code"}, "client_id": {"legacy"}, "redirect_uri": {"https://legacy/cb"}, "scope": {"openid email groups"}, "state": {"s"}}
	r, _ = get(t, cl, ts.URL+"/ui/oauth2?"+q.Encode())
	cb, _ := url.Parse(r.Header.Get("Location"))
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("legacy authorize: %d %s", r.StatusCode, r.Header.Get("Location"))
	}
	r, body = post(t, cl, ts.URL+"/oauth2/token", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://legacy/cb"}, "client_id": {"legacy"}, "client_secret": {"old"}}, [2]string{})
	var tok map[string]any
	json.Unmarshal([]byte(body), &tok)
	if r.StatusCode != 200 {
		t.Fatalf("legacy token: %d %s", r.StatusCode, body)
	}
	parts := strings.Split(tok["id_token"].(string), ".")
	var hdr map[string]string
	json.Unmarshal(b64d(parts[0]), &hdr)
	var claims map[string]any
	json.Unmarshal(b64d(parts[1]), &claims)
	// groups was asked but not mapped for legacy: not granted; email mapped but bob has none
	if hdr["alg"] != "RS256" || claims["preferred_username"] != "bob@auth.office.lan" || claims["groups"] != nil || claims["email"] != nil || tok["scope"] != "openid email" {
		t.Fatalf("legacy: %v %v %v", hdr, claims, tok["scope"])
	}
	_, body = get(t, cl, ts.URL+"/oauth2/openid/legacy/public_key.jwk")
	if !strings.Contains(body, `"kty":"RSA"`) {
		t.Fatalf("legacy jwks: %s", body)
	}
}

func TestLoginThrottle(t *testing.T) {
	s, ts, cl := newProvider(t)
	for i := 0; i < 5; i++ {
		post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"alice"}, "password": {"wrong"}}, [2]string{})
	}
	_, body := post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"alice"}, "password": {"alice-pw"}}, [2]string{})
	if !strings.Contains(body, "too many failed logins") {
		t.Fatalf("not throttled: %s", body)
	}
	s.lim.OK("127.0.0.1", "alice")
	if r, _ := post(t, cl, ts.URL+"/ui/login", url.Values{"username": {"alice"}, "password": {"alice-pw"}}, [2]string{}); r.StatusCode != 303 {
		t.Fatalf("after the block: %d", r.StatusCode)
	}
	_ = time.Second
}
