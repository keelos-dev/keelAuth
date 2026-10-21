package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/secret"
	"keelauth/internal/sys"
	"keelauth/internal/web"
)

type rig struct {
	t   *testing.T
	s   *Server
	sy  *sys.Fake
	eng *engine.Fake
	h   http.Handler
	key string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	sy := sys.NewFake()
	sy.Handle = func(line, stdin string) (string, error, bool) {
		switch {
		case strings.HasPrefix(line, KanidmBin+" recover-account"):
			return `INFO | new_password: "recovered-admin-pw"`, nil, true
		case strings.HasPrefix(line, KanidmBin+" database backup"):
			f := strings.Fields(line)
			sy.Files[f[len(f)-1]] = []byte("KANIDM-DB")
			return "Backup success!", nil, true
		case strings.HasPrefix(line, "ifconfig -a inet"):
			return "vtnet0: flags=8843<UP>\n\tinet 192.0.2.10 netmask 0xffffff00\nlo0: flags=8049<UP>\n\tinet 127.0.0.1 netmask 0xff000000\n", nil, true
		}
		return "", nil, false
	}
	eng := engine.NewFake()
	sd := testSeed(strings.Repeat("ab", 32))
	s := startServer(t, sy, eng, sd)
	s.update(func(st *State) error { st.Domain = "auth.office.lan"; return nil }, false)
	if err := s.BringUp(); err != nil {
		t.Fatalf("bring-up: %v", err)
	}
	return &rig{t: t, s: s, sy: sy, eng: eng, h: s.Handler(), key: sd.Key}
}

// testSeed is a seed with key (keel manages this keelAuth); nil key: none.
func testSeed(key string) *Seed {
	return &Seed{Magic: 1, Key: key, Port: 8441, Keel: []string{"https://169.254.77.1:443"}}
}

// startServer makes a server on sy's data as Serve would: the seed (nil: standalone), then the
// master key.
func startServer(t *testing.T, sy *sys.Fake, eng engine.Engine, sd *Seed) *Server {
	t.Helper()
	s, err := NewServer(sy, eng, "/data/keelauth", "test", log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if sd != nil {
		s.hmu.Lock()
		s.seed = sd
		s.hmu.Unlock()
	}
	if err := s.OpenMasterKey(sd); err != nil {
		t.Fatal(err)
	}
	s.dropStoredKey()
	return s
}

// call makes a request with keel's key (auth "" ), a bearer token ("Bearer x") or a cookie ("cookie:ID:CSRF").
func (r *rig) call(method, path, auth string, body any) (int, map[string]any, http.Header) {
	r.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	switch {
	case auth == "":
		req.Header.Set("Authorization", "Bearer "+r.key)
	case auth == "none":
	case strings.HasPrefix(auth, "cookie:"):
		p := strings.SplitN(auth, ":", 3)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: p[1]})
		if p[2] != "" {
			req.Header.Set("X-Keelauth-CSRF", p[2])
		}
	default:
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out, rec.Header()
}

func (r *rig) ok(method, path string, body any) map[string]any {
	r.t.Helper()
	code, out, _ := r.call(method, path, "", body)
	if code != 200 {
		r.t.Fatalf("%s %s: %d %v", method, path, code, out)
	}
	return out
}

func (r *rig) authorize() string { return string(r.sy.Files[RadAuthorize]) }

func TestBringUp(t *testing.T) {
	r := newRig(t)
	st := r.s.State()
	if pw, _ := r.s.box.Open(st.Admin); pw != "recovered-admin-pw" {
		t.Errorf("idm_admin password %q", pw)
	}
	if strings.Contains(string(r.sy.Files["/data/keelauth/state.json"]), "recovered-admin-pw") {
		t.Error("idm_admin password in clear in state.json")
	}
	if r.eng.Prepared[0] != AdminGroup {
		t.Errorf("prepared %v", r.eng.Prepared)
	}
	if _, err := r.eng.User(BindAccount); err != nil {
		t.Errorf("no bind account: %v", err)
	}
	if !strings.Contains(string(r.sy.Files[RadClients]), "client localhost") {
		t.Errorf("clients.conf:\n%s", r.sy.Files[RadClients])
	}
	if !r.sy.Ran("service radiusd onestart") && !r.sy.Ran("service radiusd onerestart") {
		t.Error("radiusd not started")
	}
	// the bind account is not a user of the API
	out := r.ok("GET", "/v1/users", nil)
	if n := len(out["users"].([]any)); n != 0 {
		t.Errorf("%d users, want 0 (bind account hidden)", n)
	}
	cfg := r.s.KanidmConfig(st, true)
	for _, want := range []string{`domain = "auth.office.lan"`, `origin = "https://auth.office.lan:8443"`, `ldapbindaddress = "0.0.0.0:636"`, `db_path = "/data/keelauth/kanidm/kanidm.db"`, `db_fs_type = "zfs"`} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config.toml lacks %s:\n%s", want, cfg)
		}
	}
}

func TestUsersAndNTHash(t *testing.T) {
	r := newRig(t)
	rev := r.s.State().Revision
	u := r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice Wang", "password": "Keel-Auth-2026", "mail": "alice@office.lan"})
	if u["has_nt"] != true || u["must_change"] != false || u["password"] != nil {
		t.Errorf("user %v", u)
	}
	d := r.s.State().Users["alice"]
	nt, err := r.s.box.Open(d.NT)
	if err != nil || nt != secret.NTHash("Keel-Auth-2026") {
		t.Fatalf("nt %q %v", nt, err)
	}
	if strings.Contains(string(r.sy.Files["/data/keelauth/state.json"]), nt) {
		t.Error("NT hash in clear in state.json")
	}
	if r.s.State().Revision <= rev {
		t.Error("revision did not go up")
	}
	want := "alice\tNT-Password := 0x" + strings.ToUpper(nt)
	if !strings.Contains(r.authorize(), want) {
		t.Errorf("authorize lacks %q:\n%s", want, r.authorize())
	}
	if ok, _ := r.eng.CheckPassword("alice", "Keel-Auth-2026"); !ok {
		t.Error("engine does not have the password")
	}
	// a generated password: returned once, must change
	b := r.ok("POST", "/v1/users", map[string]any{"name": "bob"})
	pw, _ := b["password"].(string)
	if len(pw) != 19 || b["must_change"] != true {
		t.Errorf("generated %v", b)
	}
	if g := r.ok("GET", "/v1/users/bob", nil); g["password"] != nil {
		t.Error("password shown again")
	}
	// weak password: refused, no half-made user
	code, out, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "carol", "password": "short"})
	if code != 400 || out["code"] != "weak_password" {
		t.Errorf("weak: %d %v", code, out)
	}
	if _, err := r.eng.User("carol"); err == nil {
		t.Error("carol made despite the weak password")
	}
	// names
	for _, n := range []string{"Alice", "1x", "idm_admin", "admin", BindAccount, ""} {
		if code, _, _ := r.call("POST", "/v1/users", "", map[string]any{"name": n, "password": "Keel-Auth-2026"}); code != 400 && code != 409 {
			t.Errorf("name %q: %d", n, code)
		}
	}
	if code, _, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "alice", "password": "Keel-Auth-2026"}); code != 409 {
		t.Errorf("duplicate: %d", code)
	}
	// disable: off RADIUS; enable: back
	r.ok("PATCH", "/v1/users/alice", map[string]any{"enabled": false})
	if strings.Contains(r.authorize(), "alice") {
		t.Error("disabled user still in RADIUS")
	}
	r.ok("PATCH", "/v1/users/alice", map[string]any{"enabled": true, "display_name": "Alice W."})
	if !strings.Contains(r.authorize(), "alice") {
		t.Error("enabled user not in RADIUS")
	}
	// reset password
	p := r.ok("POST", "/v1/users/alice/password", map[string]any{})
	np := p["password"].(string)
	nt2, _ := r.s.box.Open(r.s.State().Users["alice"].NT)
	if nt2 != secret.NTHash(np) || !r.s.State().Users["alice"].MustChange {
		t.Error("reset: NT hash or must_change not updated")
	}
	// delete
	r.ok("DELETE", "/v1/users/alice", nil)
	if strings.Contains(r.authorize(), "alice") || r.s.State().Users["alice"] != nil {
		t.Error("deleted user left behind")
	}
	if code, _, _ := r.call("GET", "/v1/users/alice", "", nil); code != 404 {
		t.Errorf("deleted user: %d", code)
	}
}

func TestGroupsAndLastAdmin(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "ben", "password": "Keel-Auth-2026"})
	g := r.ok("POST", "/v1/groups", map[string]any{"name": "office", "members": []string{"anna", "ben"}})
	if len(g["members"].([]any)) != 2 {
		t.Errorf("group %v", g)
	}
	r.ok("POST", "/v1/groups/office/members", map[string]any{"remove": []string{"ben"}})
	if u := r.ok("GET", "/v1/users/ben", nil); len(u["groups"].([]any)) != 0 {
		t.Errorf("ben still in office: %v", u)
	}
	if code, _, _ := r.call("POST", "/v1/groups", "", map[string]any{"name": "ben"}); code != 409 {
		t.Errorf("group named like a user: %d", code)
	}
	if code, _, _ := r.call("POST", "/v1/groups", "", map[string]any{"name": "x", "members": []string{"nobody"}}); code != 400 {
		t.Errorf("unknown member: %d", code)
	}
	// anna is the last admin
	for _, c := range []struct {
		m, p string
		b    any
	}{{"PATCH", "/v1/users/anna", map[string]any{"enabled": false}}, {"PATCH", "/v1/users/anna", map[string]any{"groups": []string{}}},
		{"DELETE", "/v1/users/anna", nil}, {"PATCH", "/v1/groups/" + AdminGroup, map[string]any{"members": []string{}}}} {
		if code, _, _ := r.call(c.m, c.p, "", c.b); code != 409 {
			t.Errorf("%s %s on the last admin: %d", c.m, c.p, code)
		}
	}
	if code, _, _ := r.call("DELETE", "/v1/groups/"+AdminGroup, "", nil); code != 409 {
		t.Errorf("delete admin group: %d", code)
	}
	// RADIUS limited to a group
	r.ok("PUT", "/v1/radius", map[string]any{"group": "office"})
	if strings.Contains(r.authorize(), "ben") || !strings.Contains(r.authorize(), "anna") {
		t.Errorf("radius group:\n%s", r.authorize())
	}
	if code, _, _ := r.call("DELETE", "/v1/groups/office", "", nil); code != 409 {
		t.Errorf("deleting the RADIUS group: %d", code)
	}
	r.ok("PUT", "/v1/radius", map[string]any{"group": ""})
	r.ok("DELETE", "/v1/groups/office", nil)
}

func login(r *rig, name, pw string) (string, string, int) {
	code, out, hd := r.call("POST", "/login", "none", map[string]any{"name": name, "password": pw})
	if code != 200 {
		return "", "", code
	}
	ck := ""
	for _, c := range (&http.Response{Header: hd}).Cookies() {
		if c.Name == sessionCookie {
			ck = c.Value
		}
	}
	return ck, out["csrf"].(string), code
}

func TestLoginSessions(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "ben", "password": "Keel-Auth-2026", "must_change": true})
	if _, _, code := login(r, "anna", "wrong-password-1"); code != 401 {
		t.Errorf("wrong password: %d", code)
	}
	ck, csrf, code := login(r, "anna", "Keel-Auth-2026")
	if code != 200 || ck == "" {
		t.Fatalf("login: %d", code)
	}
	if code, out, _ := r.call("GET", "/session", "cookie:"+ck+":", nil); code != 200 || out["admin"] != true {
		t.Errorf("session: %d %v", code, out)
	}
	if code, _, _ := r.call("GET", "/v1/users", "cookie:"+ck+":", nil); code != 200 {
		t.Errorf("admin GET: %d", code)
	}
	if code, out, _ := r.call("POST", "/v1/groups", "cookie:"+ck+":", map[string]any{"name": "g1"}); code != 403 || out["code"] != "csrf" {
		t.Errorf("no CSRF: %d %v", code, out)
	}
	if code, _, _ := r.call("POST", "/v1/groups", "cookie:"+ck+":"+csrf, map[string]any{"name": "g1"}); code != 200 {
		t.Errorf("with CSRF: %d", code)
	}
	// ben: not an admin, must change
	bk, bcsrf, _ := login(r, "ben", "Keel-Auth-2026")
	if code, out, _ := r.call("GET", "/session", "cookie:"+bk+":", nil); out["must_change"] != true || out["admin"] != false {
		t.Errorf("ben's session: %d %v", code, out)
	}
	if code, _, _ := r.call("GET", "/v1/users", "cookie:"+bk+":", nil); code != 403 {
		t.Errorf("non-admin: %d", code)
	}
	if code, _, _ := r.call("POST", "/password", "cookie:"+bk+":"+bcsrf, map[string]any{"old": "nope-nope-nope", "new": "Ben-Picks-2026"}); code != 400 {
		t.Errorf("wrong old password: %d", code)
	}
	if code, out, _ := r.call("POST", "/password", "cookie:"+bk+":"+bcsrf, map[string]any{"old": "Keel-Auth-2026", "new": "Ben-Picks-2026"}); code != 200 {
		t.Fatalf("own password: %d %v", code, out)
	}
	if r.s.State().Users["ben"].MustChange {
		t.Error("must_change not cleared")
	}
	nt, _ := r.s.box.Open(r.s.State().Users["ben"].NT)
	if nt != secret.NTHash("Ben-Picks-2026") {
		t.Error("own password: NT hash not updated")
	}
	// disabling ends ben's session; logout ends anna's
	r.ok("PATCH", "/v1/users/ben", map[string]any{"enabled": false})
	if code, _, _ := r.call("GET", "/session", "cookie:"+bk+":", nil); code != 401 {
		t.Errorf("disabled user's session: %d", code)
	}
	if _, _, code := login(r, "ben", "Ben-Picks-2026"); code != 401 {
		t.Errorf("disabled login: %d", code)
	}
	r.call("POST", "/logout", "cookie:"+ck+":", nil)
	if code, _, _ := r.call("GET", "/session", "cookie:"+ck+":", nil); code != 401 {
		t.Errorf("after logout: %d", code)
	}
	// too many failures
	for i := 0; i < failLimit; i++ {
		login(r, "anna", "wrong-password-1")
	}
	if _, _, code := login(r, "anna", "Keel-Auth-2026"); code != 429 {
		t.Errorf("after %d failures: %d", failLimit, code)
	}
	// keel's key: admin, via keel, no CSRF
	if code, out, _ := r.call("GET", "/session", "", nil); code != 200 || out["via_keel"] != true {
		t.Errorf("keel's session: %d %v", code, out)
	}
}

func TestAccessKinds(t *testing.T) {
	r := newRig(t)
	if code, _, _ := r.call("GET", "/v1/status", "none", nil); code != 401 {
		t.Errorf("no auth: %d", code)
	}
	if code, _, _ := r.call("GET", "/v1/status", "Bearer wrong", nil); code != 401 {
		t.Errorf("wrong key: %d", code)
	}
	// the internal link: only the key, also for the web page
	in := r.s.internalOnly(r.h)
	for _, c := range []struct {
		auth string
		want int
	}{{"", 200}, {"Bearer nope", 401}} {
		req := httptest.NewRequest("GET", "/", nil)
		if c.auth == "" {
			req.Header.Set("Authorization", "Bearer "+r.key)
		} else {
			req.Header.Set("Authorization", c.auth)
		}
		rec := httptest.NewRecorder()
		in.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("internal %q: %d", c.auth, rec.Code)
		}
	}
	tok := r.ok("POST", "/v1/tokens", map[string]any{"name": "claude"})["token"].(string)
	key := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "nas-a"})["key"].(string)
	if !strings.HasPrefix(tok, "kat_") || !strings.HasPrefix(key, "kas_") {
		t.Fatalf("token %q key %q", tok, key)
	}
	if strings.Contains(string(r.sy.Files["/data/keelauth/state.json"]), tok) {
		t.Error("token in clear")
	}
	// an MCP token: only /mcp; a sync key: only the sync
	if code, _, _ := r.call("GET", "/v1/users", "Bearer "+tok, nil); code != 403 {
		t.Errorf("token on the API: %d", code)
	}
	if code, _, _ := r.call("GET", "/v1/sync/accounts", "Bearer "+tok, nil); code != 403 {
		t.Errorf("token on sync: %d", code)
	}
	if code, _, _ := r.call("GET", "/v1/users", "Bearer "+key, nil); code != 403 {
		t.Errorf("sync key on the API: %d", code)
	}
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026"})
	code, out, _ := r.call("GET", "/v1/sync/accounts", "Bearer "+key, nil)
	if code != 200 {
		t.Fatalf("sync: %d %v", code, out)
	}
	us := out["users"].([]any)
	if len(us) != 1 || us[0].(map[string]any)["nt_hash"] != secret.NTHash("Keel-Auth-2026") {
		t.Errorf("sync users %v", us)
	}
	rev := int(out["revision"].(float64))
	if _, out, _ := r.call("GET", "/v1/sync/accounts?since="+itoa(rev), "Bearer "+key, nil); out["unchanged"] != true {
		t.Errorf("since: %v", out)
	}
	r.ok("POST", "/v1/users/anna/password", map[string]any{"password": "Anna-New-2026"})
	if _, out, _ := r.call("GET", "/v1/sync/accounts?since="+itoa(rev), "Bearer "+key, nil); out["unchanged"] == true {
		t.Error("revision did not change with a password")
	}
	// revoked
	id := r.ok("GET", "/v1/sync/keys", nil)["keys"].([]any)[0].(map[string]any)["id"].(string)
	r.ok("DELETE", "/v1/sync/keys/"+id, nil)
	if code, _, _ := r.call("GET", "/v1/sync/accounts", "Bearer "+key, nil); code != 401 {
		t.Errorf("revoked key: %d", code)
	}
}

func mcpCall(r *rig, auth string, msg string) (int, map[string]any) {
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(msg))
	req.Header.Set("Content-Type", "application/json")
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	var out map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestMCP(t *testing.T) {
	r := newRig(t)
	tok := "Bearer " + r.ok("POST", "/v1/tokens", map[string]any{"name": "claude"})["token"].(string)
	if code, _ := mcpCall(r, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`); code != 401 {
		t.Errorf("no token: %d", code)
	}
	code, out := mcpCall(r, tok, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`)
	if code != 200 || out["result"].(map[string]any)["serverInfo"].(map[string]any)["name"] != "keelauth" {
		t.Fatalf("initialize: %d %v", code, out)
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	names := []string{}
	for _, x := range out["result"].(map[string]any)["tools"].([]any) {
		names = append(names, x.(map[string]any)["name"].(string))
	}
	for _, want := range []string{"status", "user_list", "user_add", "user_disable", "user_enable", "user_reset_password", "group_list", "group_add", "group_members", "oidc_list", "oidc_create", "radius_list", "radius_client_add", "backup_now"} {
		if !strings.Contains(" "+strings.Join(names, " ")+" ", " "+want+" ") {
			t.Errorf("no tool %s in %v", want, names)
		}
	}
	text := func(out map[string]any) (string, bool) {
		res := out["result"].(map[string]any)
		return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"].(bool)
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"user_add","arguments":{"name":"dora","display_name":"Dora"}}}`)
	txt, isErr := text(out)
	if isErr || !strings.Contains(txt, `"password"`) || !strings.Contains(txt, `"must_change": true`) {
		t.Errorf("user_add: %v %s", isErr, txt)
	}
	if !strings.Contains(r.authorize(), "dora\t") {
		t.Error("user added over MCP has no NT hash in RADIUS")
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"user_disable","arguments":{"name":"dora"}}}`)
	if txt, isErr := text(out); isErr || !strings.Contains(txt, `"enabled": false`) {
		t.Errorf("user_disable: %s", txt)
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"oidc_create","arguments":{"name":"wiki","redirect_urls":["https://wiki.office.lan/cb"]}}}`)
	if txt, isErr := text(out); isErr || !strings.Contains(txt, "client_secret") || !strings.Contains(txt, "https://auth.office.lan:8443/oauth2/openid/wiki/.well-known/openid-configuration") {
		t.Errorf("oidc_create: %s", txt)
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"radius_client_add","arguments":{"name":"ap1","address":"192.0.2.20"}}}`)
	if txt, isErr := text(out); isErr || !strings.Contains(txt, "secret") {
		t.Errorf("radius_client_add: %s", txt)
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"group_members","arguments":{"group":"nope","add":["dora"]}}}`)
	if _, isErr := text(out); !isErr {
		t.Error("group_members on a missing group did not fail")
	}
	_, out = mcpCall(r, tok, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"status","arguments":{}}}`)
	if txt, isErr := text(out); isErr || !strings.Contains(txt, `"domain": "auth.office.lan"`) {
		t.Errorf("status: %s", txt)
	}
}

func TestOIDCAndRadiusClients(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/groups", map[string]any{"name": "dev"})
	o := r.ok("POST", "/v1/oidc", map[string]any{"name": "gitlab", "redirect_urls": []string{"https://gitlab.office.lan/cb"}, "scope_group": "dev"})
	if o["client_secret"] == "" || o["scope_group"] != "dev" || o["landing_url"] != "https://gitlab.office.lan/" || o["pkce"] != true {
		t.Errorf("oidc %v", o)
	}
	o = r.ok("PATCH", "/v1/oidc/gitlab", map[string]any{"scope_group": "", "pkce": false})
	if o["scope_group"] != "" || o["pkce"] != false {
		t.Errorf("patched %v", o)
	}
	c, _ := r.eng.OAuth2("gitlab")
	if len(c.ScopeMaps) != 1 || c.ScopeMaps[engine.AllPersons] == nil {
		t.Errorf("scope maps %v", c.ScopeMaps)
	}
	s1 := r.ok("POST", "/v1/oidc/gitlab/secret", nil)["client_secret"]
	s2 := r.ok("POST", "/v1/oidc/gitlab/secret", map[string]any{"reset": true})["client_secret"]
	if s1 == s2 {
		t.Error("secret not reset")
	}
	if code, _, _ := r.call("POST", "/v1/oidc", "", map[string]any{"name": "x", "redirect_urls": []string{"ftp://x"}}); code != 400 {
		t.Errorf("bad URL: %d", code)
	}
	rc := r.ok("POST", "/v1/radius/clients", map[string]any{"name": "ap1", "address": "192.0.2.20", "secret": "testing-secret-1"})
	if rc["secret"] != "testing-secret-1" {
		t.Errorf("client %v", rc)
	}
	conf := string(r.sy.Files[RadClients])
	if !strings.Contains(conf, "client ap1 {\n\tipaddr = 192.0.2.20\n\tsecret = \"testing-secret-1\"") {
		t.Errorf("clients.conf:\n%s", conf)
	}
	if strings.Contains(string(r.sy.Files["/data/keelauth/state.json"]), "testing-secret-1") {
		t.Error("RADIUS secret in clear in state.json")
	}
	for _, b := range []map[string]any{{"name": "ap2", "address": "not-an-ip"}, {"name": "ap2", "address": "10.0.0.0/8", "secret": "has space x"},
		{"name": "ap2", "address": "10.0.0.1", "secret": `quo"te-quote`}, {"name": "ap1", "address": "10.0.0.1"}} {
		if code, _, _ := r.call("POST", "/v1/radius/clients", "", b); code != 400 && code != 409 {
			t.Errorf("client %v: %d", b, code)
		}
	}
	r.ok("PATCH", "/v1/radius/clients/ap1", map[string]any{"address": "192.0.2.0/24"})
	r.ok("DELETE", "/v1/radius/clients/ap1", nil)
	if strings.Contains(string(r.sy.Files[RadClients]), "ap1") {
		t.Error("deleted client still in clients.conf")
	}
	l := r.ok("GET", "/v1/ldap", nil)
	if l["base_dn"] != "dc=auth,dc=office,dc=lan" || l["bind_dn"] != "name=keelauth-ldap,dc=auth,dc=office,dc=lan" || l["bind_password"] == "" || l["anonymous"] != false {
		t.Errorf("ldap %v", l)
	}
	l2 := r.ok("POST", "/v1/ldap/bind", map[string]any{"reset": true})
	if l2["bind_password"] == l["bind_password"] {
		t.Error("bind password not reset")
	}
	if ok, _ := r.eng.CheckPassword(BindAccount, l2["bind_password"].(string)); !ok {
		t.Error("engine does not have the new bind password")
	}
}

func TestBackupRestore(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026"})
	b := r.ok("POST", "/v1/backups", nil)
	name := b["name"].(string)
	if !backupRE.MatchString(name) {
		t.Fatalf("backup name %q", name)
	}
	bs := r.ok("GET", "/v1/backups", nil)["backups"].([]any)
	if len(bs) != 1 {
		t.Fatalf("backups %v", bs)
	}
	files, _, err := readBackupFiles(r.sy.Files["/data/keelauth/backups/"+name])
	if err != nil || string(files[kanidmBackupName]) != "KANIDM-DB" {
		t.Fatalf("backup content: %v %q", err, files[kanidmBackupName])
	}
	// change things, then restore: the NT hash comes back, the key stays
	r.ok("POST", "/v1/users/anna/password", map[string]any{"password": "Changed-Pass-2026"})
	r.ok("POST", "/v1/backups/"+name+"/restore", nil)
	if !r.sy.Ran(KanidmBin + " database restore") {
		t.Error("kanidm restore not run")
	}
	nt, _ := r.s.box.Open(r.s.State().Users["anna"].NT)
	if nt != secret.NTHash("Keel-Auth-2026") {
		t.Error("NT hash not restored")
	}
	if r.s.State().Key != "" {
		t.Error("restore put an internal key into state.json")
	}
	if code, _, _ := r.call("GET", "/v1/status", "", nil); code != 200 {
		t.Error("the internal key does not work after the restore")
	}
	if code, _, _ := r.call("POST", "/v1/backups/nope/restore", "", nil); code != 404 {
		t.Errorf("missing backup: %d", code)
	}
	// keep
	r.ok("PUT", "/v1/settings", map[string]any{"backup_keep": 1})
	later := r.s.now().AddDate(0, 0, 1)
	r.s.Now = func() time.Time { return later }
	r.ok("POST", "/v1/backups", nil)
	if n := len(r.ok("GET", "/v1/backups", nil)["backups"].([]any)); n != 1 {
		t.Errorf("%d backups kept, want 1", n)
	}
}

func TestReseal(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	k2[0] = 9
	b1, _ := secret.NewBox(k1)
	b2, _ := secret.NewBox(k2)
	st := &State{Users: map[string]*UserData{"a": {NT: b1.Seal("abc")}}, Admin: b1.Seal("adm"), Radius: Radius{Clients: []RadiusClient{{Name: "x", Secret: b1.Seal("s")}}}}
	if err := reseal(st, b1, b2); err != nil {
		t.Fatal(err)
	}
	if v, _ := b2.Open(st.Users["a"].NT); v != "abc" {
		t.Error("NT not resealed")
	}
	if v, _ := b2.Open(st.Admin); v != "adm" {
		t.Error("admin not resealed")
	}
}

func TestStaticPage(t *testing.T) {
	r := newRig(t)
	code, _, hd := r.call("GET", "/", "none", nil)
	if code != 200 || !strings.Contains(hd.Get("Content-Security-Policy"), "'sha256-") {
		t.Errorf("index: %d csp %q", code, hd.Get("Content-Security-Policy"))
	}
	if code, _, _ := r.call("GET", "/app/", "none", nil); code != 404 {
		t.Errorf("directory listing: %d", code)
	}
	// the prefix rule (docs/02 section 5): no absolute addresses in the page
	abs := regexp.MustCompile(`(?:href|src)=["']/[^/]|fetch\(["'` + "`" + `]/|api\("[A-Z]+", "/|import\(["']/`)
	fs.WalkDir(web.Static, "static", func(p string, d fs.DirEntry, err error) error {
		if d.IsDir() || strings.Contains(p, "/vendor/") || !(strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".css")) {
			return nil
		}
		b, _ := fs.ReadFile(web.Static, p)
		if m := abs.Find(b); m != nil {
			t.Errorf("%s: absolute address %q", p, m)
		}
		if strings.Contains(string(b), `url(/`) {
			t.Errorf("%s: absolute url() in CSS", p)
		}
		return nil
	})
}

func TestSeed(t *testing.T) {
	good := `{"keelauth_seed":1,"key":"` + strings.Repeat("ab", 32) + `","port":8441,"keel":["https://169.254.77.1:443"],"fingerprint":"` +
		strings.TrimSuffix(strings.Repeat("AB:", 32), ":") + `","internal":{"mac":"58:9C:FC:00:00:01","address":"169.254.77.3/24"},"domain":"auth.office.lan"}`
	sd, err := ParseSeed(append([]byte(good), make([]byte, 100)...))
	if err != nil {
		t.Fatal(err)
	}
	if SeedListen(sd) != "169.254.77.3:8441" || sd.Internal.MAC != "58:9c:fc:00:00:01" {
		t.Errorf("listen %s mac %s", SeedListen(sd), sd.Internal.MAC)
	}
	st := &State{}
	if !AdoptSeed(st, sd, true) || st.Domain != "auth.office.lan" || st.Key != "" {
		t.Errorf("adopt %+v", st)
	}
	st2 := &State{Domain: "old.lan"}
	AdoptSeed(st2, sd, false)
	if st2.Domain != "old.lan" {
		t.Error("domain changed on a non-fresh keelAuth")
	}
	for _, b := range []string{"", `{"keelnas_seed":1}`, "\x00\x00", "EFI PART"} {
		if _, err := ParseSeed([]byte(b)); err != ErrNotSeed {
			t.Errorf("%q: %v", b, err)
		}
	}
	for _, b := range []string{strings.Replace(good, `"domain":"auth.office.lan"`, `"domain":"Bad Domain"`, 1),
		strings.Replace(good, `"port":8441`, `"port":0`, 1), strings.Replace(good, `"keelauth_seed":1`, `"keelauth_seed":2`, 1)} {
		if _, err := ParseSeed([]byte(b)); err == nil || err == ErrNotSeed {
			t.Errorf("bad seed accepted: %v", err)
		}
	}
	// found on a disk by its first bytes
	r := newRig(t)
	r.sy.Handle = func(line, _ string) (string, error, bool) {
		if line == "sysctl -n kern.disks" {
			return "vtbd2 vtbd1 vtbd0 cd0", nil, true
		}
		return "", nil, false
	}
	r.sy.Heads["vtbd2"] = []byte(good)
	r.s.Heads = r.sy
	got, disk := r.s.findSeed()
	if got == nil || disk != "vtbd2" {
		t.Errorf("findSeed: %v %s", got, disk)
	}
}

func TestQuality(t *testing.T) {
	r := newRig(t)
	r.eng.Down = true
	r.s.BringUp()
	found := false
	for _, a := range r.s.Alerts() {
		if a.Code == "engine" {
			found = true
		}
	}
	if !found {
		t.Error("no engine alert while the engine is down")
	}
}

// keelOS tells keelAuth what its groups mean (keelOS docs/54 D3): shown per application with the
// missing groups; short user names by default for new applications
func TestOIDCRolesAndShortNames(t *testing.T) {
	r := newRig(t)
	o := r.ok("POST", "/v1/oidc", map[string]any{"name": "keel-host", "redirect_urls": []string{"https://192.0.2.1/sso/callback"}, "scope_group": ""})
	if o["short_username"] != true {
		t.Errorf("new app not short: %v", o)
	}
	if c, _ := r.eng.OAuth2("keel-host"); !c.ShortName {
		t.Error("engine: not short")
	}
	o = r.ok("PATCH", "/v1/oidc/keel-host", map[string]any{"short_username": false})
	if o["short_username"] != false {
		t.Errorf("patched %v", o)
	}
	r.ok("POST", "/v1/oidc", map[string]any{"name": "old", "redirect_urls": []string{"https://x.lan/cb"}, "short_username": false})
	if c, _ := r.eng.OAuth2("old"); c.ShortName {
		t.Error("asked for full names, got short")
	}
	r.ok("POST", "/v1/groups", map[string]any{"name": "keel-admins"})
	o = r.ok("PUT", "/v1/oidc/keel-host/roles", map[string]any{"by": "keelOS", "roles": map[string]string{"keel-admins": "admin", "keel-operators": "operate"}})
	if o["roles_by"] != "keelOS" || fmt.Sprint(o["missing_groups"]) != "[keel-operators]" {
		t.Errorf("roles %v", o)
	}
	l := r.ok("GET", "/v1/oidc", nil)
	if !strings.Contains(fmt.Sprint(l["clients"]), "keel-operators") {
		t.Errorf("list %v", l)
	}
	if code, _, _ := r.call("PUT", "/v1/oidc/keel-host/roles", "", map[string]any{"roles": map[string]string{"Bad Name": "x"}}); code != 400 {
		t.Errorf("bad group: %d", code)
	}
	if code, _, _ := r.call("PUT", "/v1/oidc/nope/roles", "", map[string]any{"roles": map[string]string{}}); code != 404 {
		t.Errorf("no app: %d", code)
	}
	r.ok("DELETE", "/v1/oidc/keel-host", nil)
	if _, ok := r.s.State().OIDCRoles["keel-host"]; ok {
		t.Error("roles stay after the app is gone")
	}
}

// rs256: legacy crypto (RS256 ID tokens) for applications that cannot verify ES256; default off
func TestOIDCRS256(t *testing.T) {
	r := newRig(t)
	o := r.ok("POST", "/v1/oidc", map[string]any{"name": "keel-host", "redirect_urls": []string{"https://192.0.2.1/sso/callback"}})
	if o["rs256"] != false {
		t.Errorf("default: %v", o)
	}
	if c, _ := r.eng.OAuth2("keel-host"); c.RS256 {
		t.Error("engine: rs256 by default")
	}
	r.ok("DELETE", "/v1/oidc/keel-host", nil)
	o = r.ok("POST", "/v1/oidc", map[string]any{"name": "keel-host", "redirect_urls": []string{"https://192.0.2.1/sso/callback"}, "rs256": true})
	if o["rs256"] != true {
		t.Errorf("created: %v", o)
	}
	if c, _ := r.eng.OAuth2("keel-host"); !c.RS256 {
		t.Error("engine: no rs256")
	}
	o = r.ok("PATCH", "/v1/oidc/keel-host", map[string]any{"rs256": false})
	if o["rs256"] != false {
		t.Errorf("patched: %v", o)
	}
	if c, _ := r.eng.OAuth2("keel-host"); c.RS256 {
		t.Error("engine: rs256 not cleared")
	}
	o = r.ok("PATCH", "/v1/oidc/keel-host", map[string]any{"rs256": true})
	if o["rs256"] != true || o["pkce"] != true {
		t.Errorf("patched on: %v", o)
	}
}

func TestNestedGroups(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026", "mail": "anna@example.com"})
	r.ok("POST", "/v1/groups", map[string]any{"name": "staff", "members": []string{"anna"}})
	r.ok("POST", "/v1/groups", map[string]any{"name": "app-x-admins"})
	g := r.ok("POST", "/v1/groups", map[string]any{"name": "app-x", "members": []string{"staff"}})
	if mg := g["member_groups"].([]any); len(mg) != 1 || mg[0] != "staff" || len(g["members"].([]any)) != 0 {
		t.Errorf("create with a group member: %v", g)
	}
	g = r.ok("POST", "/v1/groups/app-x/members", map[string]any{"add": []string{"app-x-admins", "anna"}})
	if mg := g["member_groups"].([]any); len(mg) != 2 || mg[0] != "app-x-admins" || mg[1] != "staff" {
		t.Errorf("member_groups: %v", g)
	}
	if m := g["members"].([]any); len(m) != 1 || m[0] != "anna" {
		t.Errorf("members stay users: %v", g)
	}
	// removing a user keeps the member groups
	g = r.ok("POST", "/v1/groups/app-x/members", map[string]any{"remove": []string{"anna"}})
	if len(g["member_groups"].([]any)) != 2 || len(g["members"].([]any)) != 0 {
		t.Errorf("after removing the user: %v", g)
	}
	for name, c := range map[string]struct {
		path string
		body any
	}{
		"self":         {"/v1/groups/app-x/members", map[string]any{"add": []string{"app-x"}}},
		"direct cycle": {"/v1/groups/staff/members", map[string]any{"add": []string{"app-x"}}},
		"unknown":      {"/v1/groups/staff/members", map[string]any{"add": []string{"nobody"}}},
		"into admins":  {"/v1/groups/" + AdminGroup + "/members", map[string]any{"add": []string{"staff"}}},
	} {
		if code, _, _ := r.call("POST", c.path, "", c.body); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	// deleting a group takes it out of the groups it was in
	r.ok("DELETE", "/v1/groups/staff", nil)
	for _, x := range r.ok("GET", "/v1/groups", nil)["groups"].([]any) {
		if x.(map[string]any)["name"] == "app-x" && len(x.(map[string]any)["member_groups"].([]any)) != 1 {
			t.Errorf("deleted group still a member: %v", x)
		}
	}
}
