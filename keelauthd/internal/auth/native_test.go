package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/url"

	"encoding/json"
	"fmt"
	"keelauth/internal/module/phone"
	"keelauth/internal/module/totp"
	"net/http/httptest"
	"strings"
	"testing"

	"keelauth/internal/engine"
	"keelauth/internal/sys"
)

// newNativeRig is newRig with the native engine (in memory): no Kanidm commands run.
func newNativeRig(t *testing.T) (*rig, *engine.Native) {
	t.Helper()
	sy := sys.NewFake()
	ran := []string{}
	sy.Handle = func(line, stdin string) (string, error, bool) {
		ran = append(ran, line)
		if strings.HasPrefix(line, "ifconfig -a inet") {
			return "vtnet0: flags=8843<UP>\n\tinet 192.0.2.10 netmask 0xffffff00\n", nil, true
		}
		return "", nil, false
	}
	eng, _ := engine.NewNative("")
	sd := testSeed(strings.Repeat("ab", 32))
	s := startServer(t, sy, eng, sd)
	s.bindNative()
	s.update(func(st *State) error { st.Domain = "auth.office.lan"; st.Engine = EngineNative; return nil }, false)
	if err := s.BringUp(); err != nil {
		t.Fatalf("bring-up: %v", err)
	}
	for _, l := range ran {
		if strings.Contains(l, "kanidm") {
			t.Fatalf("a Kanidm command ran with the native engine: %s", l)
		}
	}
	return &rig{t: t, s: s, sy: sy, h: s.Handler(), key: sd.Key}, eng
}

func TestNativeEngineRig(t *testing.T) {
	r, eng := newNativeRig(t)
	st := r.ok("GET", "/v1/status", nil)
	if st["engine"] != "native" {
		t.Fatalf("status engine: %v", st["engine"])
	}
	svc := st["services"].(map[string]any)
	if svc["store"] != true || svc["radiusd"] != true || svc["kanidmd"] != nil {
		t.Fatalf("services: %v", svc)
	}
	if r.s.State().Engine != EngineNative {
		t.Fatal("the state does not record the engine")
	}
	// the admin group and the bind account came from Prepare / ensureBindAccount
	if _, err := eng.Group(AdminGroup); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.User(BindAccount); err != nil {
		t.Fatal(err)
	}
	// a user through the API, with the password rule from the settings
	r.ok("PUT", "/v1/settings", map[string]any{"password_min_length": 10, "password_strength": "normal"})
	code, out, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "alice", "display_name": "Alice", "password": "short1", "groups": []string{AdminGroup}})
	if code != 400 || !strings.Contains(out["error"].(string), "at least 10") {
		t.Fatalf("short password: %d %v", code, out)
	}
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	if ok, _ := eng.CheckPassword("alice", "orange-kettle-7"); !ok {
		t.Fatal("password not set in the store")
	}
	if d := r.s.State().Users["alice"]; d == nil || d.NT == "" {
		t.Fatal("no NT hash kept beside the store")
	}
	// the web login works against the store
	code, out, _ = r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7"})
	if code != 200 || out["admin"] != true {
		t.Fatalf("login: %d %v", code, out)
	}
	// an OIDC client's secret is sealed in the store and readable through the API
	r.ok("POST", "/v1/oidc", map[string]any{"name": "app", "display_name": "App", "landing_url": "https://app.example/", "redirect_urls": []string{"https://app.example/cb"}})
	sec := r.ok("POST", "/v1/oidc/app/secret", map[string]any{})["client_secret"].(string)
	if sec == "" || strings.Contains(string(eng.Export()), sec) {
		t.Fatalf("secret %q in clear in the store", sec)
	}
	// backup carries the store, restore brings a deleted user back
	r.ok("POST", "/v1/backups", nil)
	bs := r.ok("GET", "/v1/backups", nil)["backups"].([]any)
	if len(bs) != 1 {
		t.Fatalf("backups: %v", bs)
	}
	name := bs[0].(map[string]any)["name"].(string)
	r.ok("POST", "/v1/users", map[string]any{"name": "bob", "password": "purple-ladder-3", "groups": []string{AdminGroup}}) // alice is not the last admin
	r.ok("DELETE", "/v1/users/alice", nil)
	if _, err := eng.User("alice"); err == nil {
		t.Fatal("alice not deleted")
	}
	r.ok("POST", "/v1/backups/"+name+"/restore", map[string]any{})
	if ok, _ := eng.CheckPassword("alice", "orange-kettle-7"); !ok {
		t.Fatal("alice not back after the restore")
	}
	if got, _ := eng.OAuth2Secret("app", false); got != sec {
		t.Fatalf("client secret after restore: %q, want %q", got, sec)
	}
}

func TestChooseEngine(t *testing.T) {
	dir := t.TempDir()
	if k := ChooseEngine(sys.NewFake(), dir); k != EngineNative {
		t.Fatalf("empty dir: %s", k)
	}
	sy := sys.NewFake()
	sy.Files[dir+"/state.json"] = []byte(`{"version":1,"engine":"native"}`)
	if k := ChooseEngine(sy, dir); k != EngineNative {
		t.Fatalf("state says native: %s", k)
	}
}

func TestNativeLDAPDirectory(t *testing.T) {
	r, eng := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "mail": "alice@example.com", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "bob", "password": "purple-ladder-3"})
	r.ok("POST", "/v1/groups", map[string]any{"name": "staff", "members": []string{"bob", AdminGroup}}) // admins nested in staff
	d := ldapDir{r.s}
	if d.BaseDN() != "dc=auth,dc=office,dc=lan" || d.Domain() != "auth.office.lan" {
		t.Fatalf("base %s domain %s", d.BaseDN(), d.Domain())
	}
	people := d.People()
	names := []string{}
	for _, p := range people {
		names = append(names, p.Name)
		if p.Name == "alice" && (strings.Join(p.Groups, ",") != AdminGroup+",staff" || p.Mails[0] != "alice@example.com") {
			t.Fatalf("alice through the nested group: %+v", p)
		}
	}
	if strings.Join(names, ",") != "alice,bob" { // the bind account is not a person here
		t.Fatalf("people: %v", names)
	}
	for _, g := range d.Groups() {
		if g.Name == "staff" && strings.Join(g.Members, ",") != "alice,bob" {
			t.Fatalf("staff flattened: %+v", g)
		}
	}
	if !d.CheckPassword("alice", "orange-kettle-7") || d.CheckPassword("alice", "x") {
		t.Fatal("password check")
	}
	dev := r.ok("POST", "/v1/ldap/devices", map[string]any{"name": "printer1"})
	tok := dev["password"].(string)
	if who, ok := d.CheckToken(tok); !ok || who != "printer1" {
		t.Fatalf("device token: %q %v", who, ok)
	}
	if _, ok := eng.FindToken("kad_nope"); ok {
		t.Fatal("unknown token found")
	}
	if svc := r.ok("GET", "/v1/status", nil)["services"].(map[string]any); svc["ldap"] != true {
		t.Fatalf("status ldap: %v", svc)
	}
}

func TestNativeOIDCProvider(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "mail": "alice@example.com", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/oidc", map[string]any{"name": "keel-host1", "display_name": "keelOS", "landing_url": "https://host1/", "redirect_urls": []string{"https://host1/sso/callback"}, "scope_group": AdminGroup})
	sec := r.ok("POST", "/v1/oidc/keel-host1/secret", map[string]any{})["client_secret"].(string)
	p, err := r.s.oidcProvider()
	if err != nil {
		t.Fatal(err)
	}
	d := oidcDir{r.s}
	if !d.CheckSecret("keel-host1", sec) || d.CheckSecret("keel-host1", "x") || !d.CheckPassword("alice", "orange-kettle-7") {
		t.Fatal("secret / password checks")
	}
	person, ok := d.Person("alice")
	if !ok || person.UUID == "" || strings.Join(person.Groups, ",") != AdminGroup || person.Mail != "alice@example.com" {
		t.Fatalf("person: %+v %v", person, ok)
	}
	if _, ok := d.Person(BindAccount); ok {
		t.Fatal("the bind account is a person")
	}
	// the provider answers through keelauthd's handler for the origin's port
	req := httptest.NewRequest("GET", "/oauth2/openid/keel-host1/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	r.s.oidcHandler(p).ServeHTTP(rec, req)
	var disc map[string]any
	json.Unmarshal(rec.Body.Bytes(), &disc)
	if rec.Code != 200 || disc["issuer"] != r.s.Origin()+"/oauth2/openid/keel-host1" {
		t.Fatalf("discovery: %d %s", rec.Code, rec.Body.String())
	}
	r.ok("DELETE", "/v1/oidc/keel-host1", nil)
	if svc := r.ok("GET", "/v1/status", nil)["services"].(map[string]any); svc["oidc"] != true {
		t.Fatalf("status oidc: %v", svc)
	}
}

// TestAccessRights: a service belongs to a group and whoever is in the group has it
// (access.go); a service without a group is open to every account.
func TestAccessRights(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	r.ok("POST", "/v1/oidc", map[string]any{"name": "app1", "display_name": "App 1", "landing_url": "https://app1/", "redirect_urls": []string{"https://app1/cb"}})
	key := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "Gate A"})["key"].(string)
	consumers := func() map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, c := range r.ok("GET", "/v1/consumers", nil)["consumers"].([]any) {
			m := c.(map[string]any)
			out[m["id"].(string)] = m
		}
		return out
	}
	cons := consumers()
	gate := ""
	for id := range cons {
		if strings.HasPrefix(id, "sync:") {
			gate = id
		}
	}
	if len(cons) != 5 || cons["smb"] == nil || cons["ldap"] == nil || cons["wifi"] == nil || cons["oidc:app1"] == nil || gate == "" {
		t.Fatalf("consumers: %v", cons)
	}
	// nothing has a group yet: everything is everybody's, and the usual names are offered
	if cons["smb"]["group"] != "" || cons["smb"]["suggest"] != "samba" || cons[gate]["suggest"] != "gate-a" || cons["oidc:app1"]["suggest"] != "app1-users" || cons["wifi"]["users"] != float64(2) {
		t.Fatalf("before any group: %v", cons)
	}
	d := ldapDir{r.s}
	people := func() string {
		names := []string{}
		for _, p := range d.People() {
			names = append(names, p.Name)
		}
		return strings.Join(names, ",")
	}
	syncNames := func(auth string) string {
		code, sy, _ := r.call("GET", "/v1/sync/accounts", auth, nil)
		if code != 200 {
			t.Fatalf("sync: %d %v", code, sy)
		}
		got := []string{}
		for _, u := range sy["users"].([]any) {
			got = append(got, u.(map[string]any)["name"].(string))
		}
		return strings.Join(got, ",")
	}
	if people() != "alice,carol" || syncNames("Bearer "+key) != "alice,carol" {
		t.Fatalf("open services: %s / %s", people(), syncNames("Bearer "+key))
	}
	// the gate is for the members of telework: the group is made, empty, and nobody is served
	if code, out, _ := r.call("PUT", "/v1/consumers/nope", "", map[string]any{"group": "x"}); code != 404 {
		t.Fatalf("unknown service: %d %v", code, out)
	}
	if code, out, _ := r.call("PUT", "/v1/consumers/"+gate, "", map[string]any{"group": "Bad Name"}); code != 400 {
		t.Fatalf("bad group name: %d %v", code, out)
	}
	c := r.ok("PUT", "/v1/consumers/"+gate, map[string]any{"group": "telework"})
	if c["group"] != "telework" || c["users"] != float64(0) {
		t.Fatalf("bound: %v", c)
	}
	if _, err := r.s.Eng.Group("telework"); err != nil {
		t.Fatalf("the group was not made: %v", err)
	}
	if syncNames("Bearer "+key) != "" {
		t.Fatalf("an empty group serves %q", syncNames("Bearer "+key))
	}
	// carol joins: she has the service; alice does not
	r.ok("PATCH", "/v1/groups/telework", map[string]any{"members": []string{"carol"}})
	if syncNames("Bearer "+key) != "carol" {
		t.Fatalf("after carol joined: %q", syncNames("Bearer "+key))
	}
	for _, g := range r.ok("GET", "/v1/groups", nil)["groups"].([]any) {
		if gm := g.(map[string]any); gm["name"] == "telework" {
			if sv, _ := gm["services"].([]any); len(sv) != 1 || sv[0] != gate {
				t.Fatalf("what the group gives: %v", gm["services"])
			}
		}
	}
	// through a group in the group too
	r.ok("POST", "/v1/groups", map[string]any{"name": "staff", "members": []string{"alice"}})
	r.ok("PATCH", "/v1/groups/telework", map[string]any{"members": []string{"carol", "staff"}})
	if syncNames("Bearer "+key) != "alice,carol" {
		t.Fatalf("nested: %q", syncNames("Bearer "+key))
	}
	r.ok("PATCH", "/v1/groups/telework", map[string]any{"members": []string{"carol"}})
	// LDAP, Wi-Fi, an SSO application and the shares each with a group of their own
	r.ok("PUT", "/v1/consumers/ldap", map[string]any{"group": "ldap"})
	r.ok("PUT", "/v1/consumers/wifi", map[string]any{"group": "wifi"})
	r.ok("PUT", "/v1/consumers/oidc:app1", map[string]any{"group": "app1-users"})
	r.ok("PUT", "/v1/consumers/smb", map[string]any{"group": "samba"})
	r.ok("PATCH", "/v1/groups/ldap", map[string]any{"members": []string{"carol"}})
	r.ok("PATCH", "/v1/groups/wifi", map[string]any{"members": []string{"alice"}})
	r.ok("PATCH", "/v1/groups/app1-users", map[string]any{"members": []string{"alice"}})
	r.ok("PATCH", "/v1/groups/samba", map[string]any{"members": []string{"alice"}})
	if people() != "carol" || !d.CheckPassword("carol", "purple-ladder-3") || d.CheckPassword("alice", "orange-kettle-7") {
		t.Fatalf("ldap by its group: %s", people())
	}
	od := oidcDir{r.s}
	if od.Allowed("carol", "app1") || !od.Allowed("alice", "app1") {
		t.Fatal("oidc by its group")
	}
	// the file FreeRADIUS reads, not just what it would be: adding alice to wifi rewrites it
	if auth := r.authorize(); strings.Contains(auth, "carol") || !strings.Contains(auth, "alice") {
		t.Fatalf("radius users:\n%s", r.authorize())
	}
	// keel reads the accounts for the shares (it hands them to keelNAS): the samba group
	if syncNames("") != "alice" {
		t.Fatalf("keel's sync, for the shares: %q", syncNames(""))
	}
	// a group that decides about a service is not deleted from under it
	if code, out, _ := r.call("DELETE", "/v1/groups/telework", "", nil); code != 409 {
		t.Fatalf("deleting a service's group: %d %v", code, out)
	}
	// open to everybody again; then the group can go
	if c := r.ok("PUT", "/v1/consumers/"+gate, map[string]any{"group": ""}); c["group"] != "" || c["users"] != float64(2) {
		t.Fatalf("unbound: %v", c)
	}
	r.ok("DELETE", "/v1/groups/telework", nil)
	// the lists accounts and groups had before are taken and not kept
	u := r.ok("PATCH", "/v1/users/carol", map[string]any{"access": []string{"ldap"}})
	if _, has := u["access"]; has {
		t.Fatalf("an account still has a list of its own: %v", u)
	}
}

// TestSyncKeyForAGateway: a key made with its group, without secrets and wanting an
// authenticator app: the accounts of the group without their hashes, and POST
// /v1/sync/verify for the login (verify.go).
func TestSyncKeyForAGateway(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("PUT", "/v1/modules/totp", map[string]any{"enabled": true})
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	r.ok("POST", "/v1/users", map[string]any{"name": "dave", "password": "yellow-window-5"})
	if code, out, _ := r.call("POST", "/v1/tokens", "", map[string]any{"name": "ai", "group": "telework"}); code != 400 {
		t.Fatalf("a group on an MCP token: %d %v", code, out)
	}
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "portal", "group": "telework", "secrets": false, "require_totp": true})
	key := "Bearer " + k["key"].(string)
	if k["group"] != "telework" || k["secrets"] != false || k["require_totp"] != true {
		t.Fatalf("the key: %v", k)
	}
	listed := r.ok("GET", "/v1/sync/keys", nil)["keys"].([]any)[0].(map[string]any)
	if listed["group"] != "telework" || listed["secrets"] != false || listed["require_totp"] != true || listed["key"] != nil {
		t.Fatalf("the key in the list: %v", listed)
	}
	r.ok("PATCH", "/v1/groups/telework", map[string]any{"members": []string{"alice", "carol"}})
	// alice sets up her authenticator app
	code, out, hd := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7"})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	var sid string
	for _, c := range hd.Values("Set-Cookie") {
		if strings.HasPrefix(c, sessionCookie+"=") {
			sid = strings.SplitN(strings.TrimPrefix(c, sessionCookie+"="), ";", 2)[0]
		}
	}
	page := "cookie:" + sid + ":" + out["csrf"].(string)
	_, e, _ := r.call("POST", "/v1/totp/enroll", page, map[string]any{})
	secret := e["secret"].(string)
	good := func() string { c, _ := totp.Code(secret, totp.Step(r.s.now())); return c }
	fresh := func() { totpMu.Lock(); delete(totpLast, "alice"); totpMu.Unlock() } // a new step for the test
	fresh()
	t.Cleanup(fresh) // (the steps used are kept by name for the whole program: the next test has an alice too)
	if code, out, _ := r.call("POST", "/v1/totp/confirm", page, map[string]any{"code": good()}); code != 200 {
		t.Fatalf("confirm: %d %v", code, out)
	}
	fresh()
	// the accounts of the group, who has an app, and no hash of anybody
	code, sy, _ := r.call("GET", "/v1/sync/accounts", key, nil)
	if code != 200 || sy["secrets"] != false || len(sy["users"].([]any)) != 2 {
		t.Fatalf("sync: %d %v", code, sy)
	}
	for _, u := range sy["users"].([]any) {
		m := u.(map[string]any)
		if m["nt_hash"] != "" || m["password_hash"] != nil || m["totp"] != (m["name"] == "alice") || m["password_set_at"] == "" ||
			(m["totp_set_at"] != "") != (m["name"] == "alice") {
			t.Fatalf("a synced account: %v", m)
		}
	}
	// keel's own sync still carries the hashes (keelNAS needs them)
	_, sy, _ = r.call("GET", "/v1/sync/accounts", "", nil)
	if sy["secrets"] != true || sy["users"].([]any)[0].(map[string]any)["nt_hash"] == "" {
		t.Fatalf("keel's sync lost the hashes: %v", sy)
	}
	verify := func(name, password, code string) (int, map[string]any) {
		c, out, _ := r.call("POST", "/v1/sync/verify", key, map[string]any{"name": name, "password": password, "code": code})
		return c, out
	}
	if c, out := verify("alice", "orange-kettle-7", ""); c != 401 || out["code"] != "totp_required" {
		t.Fatalf("no code: %d %v", c, out)
	}
	if c, out := verify("alice", "orange-kettle-7", "000000"); c != 401 || out["code"] != "bad_code" {
		t.Fatalf("wrong code: %d %v", c, out)
	}
	if c, out := verify("alice", "wrong", good()); c != 401 || out["code"] != "bad_login" {
		t.Fatalf("wrong password: %d %v", c, out)
	}
	if c, out := verify("nobody", "x", ""); c != 401 || out["code"] != "bad_login" {
		t.Fatalf("no such account: %d %v", c, out)
	}
	c, out2 := verify("alice", "orange-kettle-7", good())
	if c != 200 || out2["name"] != "alice" || out2["totp"] != true || out2["must_change"] != false || out2["password_set_at"] == "" || out2["totp_set_at"] == "" {
		t.Fatalf("right: %d %v", c, out2)
	}
	setAt := out2["totp_set_at"]
	// who cannot come in through this key yet: carol (no authenticator), on the services card and the user list
	seen := false
	for _, c := range r.ok("GET", "/v1/consumers", nil)["consumers"].([]any) {
		if m := c.(map[string]any); m["kind"] == "sync" && m["name"] == "portal" {
			seen = true
			if m["require_totp"] != true || fmt.Sprint(m["no_totp"]) != "[carol]" || m["users"] != float64(2) {
				t.Fatalf("the gateway's service: %v", m)
			}
		}
	}
	if !seen {
		t.Fatal("the gateway's key is not among the services")
	}
	for _, u := range r.ok("GET", "/v1/users", nil)["users"].([]any) {
		if m := u.(map[string]any); m["totp"] != (m["name"] == "alice") || (m["totp_set_at"] != "") != (m["name"] == "alice") {
			t.Fatalf("user list, totp: %v", m)
		}
	}
	if gs, _ := out2["groups"].([]any); len(gs) != 2 {
		t.Fatalf("groups in the answer: %v", out2["groups"])
	}
	// the same code once more in its step: refused, as at the page
	if c, out := verify("alice", "orange-kettle-7", good()); c != 401 || out["code"] != "bad_code" {
		t.Fatalf("replay: %d %v", c, out)
	}
	// carol is in the group and has no app: this key lets nobody in on a password alone
	if c, out := verify("carol", "purple-ladder-3", ""); c != 403 || out["code"] != "totp_not_set" {
		t.Fatalf("no app: %d %v", c, out)
	}
	// dave's password is right and he is not in the group; a wrong one says nothing of that
	if c, out := verify("dave", "yellow-window-5", ""); c != 403 || out["code"] != "not_allowed" {
		t.Fatalf("not in the group: %d %v", c, out)
	}
	if c, out := verify("dave", "wrong", ""); c != 401 || out["code"] != "bad_login" {
		t.Fatalf("not in the group, wrong password: %d %v", c, out)
	}
	// disabled: no way in, and nothing said of it to who has not the password (this engine
	// takes no password of a disabled account at all: the same answer as a wrong one)
	r.ok("PATCH", "/v1/users/carol", map[string]any{"enabled": false})
	if c, out := verify("carol", "purple-ladder-3", ""); c != 401 || (out["code"] != "disabled" && out["code"] != "bad_login") {
		t.Fatalf("disabled: %d %v", c, out)
	}
	if c, out := verify("carol", "wrong", ""); c != 401 || out["code"] != "bad_login" {
		t.Fatalf("disabled, wrong password: %d %v", c, out)
	}
	// only the sync interface's callers
	if c, out, _ := r.call("POST", "/v1/sync/verify", page, map[string]any{"name": "alice", "password": "orange-kettle-7"}); c != 403 {
		t.Fatalf("a page session may verify: %d %v", c, out)
	}
	// wrong tries count: the sixth is not even looked at
	for i := 0; i < 5; i++ {
		verify("dave", "wrong", "")
	}
	if c, out := verify("dave", "yellow-window-5", ""); c != 429 || out["code"] != "too_many" {
		t.Fatalf("after five wrong tries: %d %v", c, out)
	}
	// the authenticator taken away: the sync says so (totp_set_at empty), so a gateway drops alice's computers
	r.ok("DELETE", "/v1/totp?user=alice", nil)
	_, sy2, _ := r.call("GET", "/v1/sync/accounts", key, nil)
	for _, u := range sy2["users"].([]any) {
		if m := u.(map[string]any); m["name"] == "alice" && (m["totp"] != false || m["totp_set_at"] != "") {
			t.Fatalf("alice without an authenticator (was set at %v): %v", setAt, m)
		}
	}
	// the key revoked: its group is no service's any more
	r.ok("DELETE", "/v1/sync/keys/"+k["id"].(string), nil)
	if len(r.s.State().ServiceGroups) != 0 {
		t.Fatalf("bindings left: %v", r.s.State().ServiceGroups)
	}
	if c, _, _ := r.call("POST", "/v1/sync/verify", key, map[string]any{"name": "alice", "password": "orange-kettle-7"}); c != 401 {
		t.Fatalf("a revoked key verifies: %d", c)
	}
}

// TestMailGroup: a mail server with a group: whoever is in it has a mailbox at every domain
// the server offers, without a tick per domain (maildomains.go).
func TestMailGroup(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})
	key := "Bearer " + k["key"].(string)
	r.call("PUT", "/v1/sync/offers", key, map[string]any{"mail_domains": []string{"acme.example", "other.example"}})
	id := "sync:" + k["id"].(string)
	cons := r.ok("GET", "/v1/consumers", nil)
	if td := cons["mail_domains_ticked"].([]any); len(td) != 2 {
		t.Fatalf("domains to tick while the mail server has no group: %v", td)
	}
	for _, c := range cons["consumers"].([]any) {
		if m := c.(map[string]any); m["id"] == id && m["suggest"] != "mail" {
			t.Fatalf("a mail server's usual group: %v", m)
		}
	}
	r.ok("PATCH", "/v1/users/carol", map[string]any{"mail_domains": []string{"acme.example"}})
	r.ok("PUT", "/v1/consumers/"+id, map[string]any{"group": "mail"})
	if td := r.ok("GET", "/v1/consumers", nil)["mail_domains_ticked"].([]any); len(td) != 0 {
		t.Fatalf("domains to tick once the mail server has a group: %v", td)
	}
	// nobody is in the group yet: carol's tick no longer makes a mailbox
	if as, _ := r.ok("GET", "/v1/users/carol", nil)["addresses"].([]any); len(as) != 0 {
		t.Fatalf("carol outside the group: %v", as)
	}
	r.ok("PATCH", "/v1/groups/mail", map[string]any{"members": []string{"alice"}})
	if as, _ := r.ok("GET", "/v1/users/alice", nil)["addresses"].([]any); len(as) != 2 || as[0] != "alice@acme.example" || as[1] != "alice@other.example" {
		t.Fatalf("alice in the group: %v", as)
	}
	code, sy, _ := r.call("GET", "/v1/sync/accounts", key, nil)
	if us := sy["users"].([]any); code != 200 || len(us) != 1 || len(us[0].(map[string]any)["addresses"].([]any)) != 2 {
		t.Fatalf("the mail server's accounts: %d %v", code, sy["users"])
	}
	// the mail server takes on a domain: every member has it at once
	r.call("PUT", "/v1/sync/offers", key, map[string]any{"mail_domains": []string{"acme.example", "other.example", "third.example"}})
	if as, _ := r.ok("GET", "/v1/users/alice", nil)["addresses"].([]any); len(as) != 3 {
		t.Fatalf("after a new domain: %v", as)
	}
}

func TestMailDomains(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "mail": "alice@gmail.example", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	key := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})["key"].(string)
	if code, _, _ := r.call("PUT", "/v1/sync/offers", "", map[string]any{"mail_domains": []string{"acme.example"}}); code != 403 {
		t.Fatalf("keel's key may not offer: %d", code)
	}
	if code, out, _ := r.call("PUT", "/v1/sync/offers", "Bearer "+key, map[string]any{"mail_domains": []string{"Acme.example", "other.example", "bad_domain"}}); code != 400 {
		t.Fatalf("bad domain: %d %v", code, out)
	}
	code, out, _ := r.call("PUT", "/v1/sync/offers", "Bearer "+key, map[string]any{"mail_domains": []string{"Acme.example", "other.example"}})
	if code != 200 || len(out["mail_domains"].([]any)) != 2 {
		t.Fatalf("offers: %d %v", code, out)
	}
	if ds := r.ok("GET", "/v1/consumers", nil)["mail_domains"].([]any); len(ds) != 2 || ds[0] != "acme.example" {
		t.Fatalf("consumers mail_domains: %v", ds)
	}
	if code, _, _ := r.call("PATCH", "/v1/users/alice", "", map[string]any{"mail_domains": []string{"nowhere.example"}}); code != 400 {
		t.Fatalf("unoffered domain accepted: %d", code)
	}
	u := r.ok("PATCH", "/v1/users/alice", map[string]any{"mail_domains": []string{"acme.example", "other.example"}})
	if as, _ := u["addresses"].([]any); len(as) != 2 || as[0] != "alice@acme.example" {
		t.Fatalf("addresses: %v", u["addresses"])
	}
	// LDAP and the sync see the mailboxes
	for _, p := range (ldapDir{r.s}).People() {
		if p.Name == "alice" && strings.Join(p.Mails, ",") != "alice@gmail.example,alice@acme.example,alice@other.example" {
			t.Fatalf("ldap mails: %v", p.Mails)
		}
	}
	_, sy, _ := r.call("GET", "/v1/sync/accounts", "Bearer "+key, nil)
	su := sy["users"].([]any)[0].(map[string]any)
	if len(su["addresses"].([]any)) != 2 || su["mail"] != "alice@gmail.example" || len(sy["mail_domains"].([]any)) != 2 {
		t.Fatalf("sync: %v", su)
	}
	// keelMail drops other.example: alice loses that mailbox
	r.call("PUT", "/v1/sync/offers", "Bearer "+key, map[string]any{"mail_domains": []string{"acme.example"}})
	u = r.ok("GET", "/v1/users/alice", nil)
	if as, _ := u["addresses"].([]any); len(as) != 1 || as[0] != "alice@acme.example" {
		t.Fatalf("after the drop: %v", u["addresses"])
	}
	if md, _ := u["mail_domains"].([]any); len(md) != 1 {
		t.Fatalf("mail_domains after the drop: %v", md)
	}
	// a new user ticks a domain at creation
	b := r.ok("POST", "/v1/users", map[string]any{"name": "bob", "password": "purple-ladder-3", "mail_domains": []string{"acme.example"}})
	if as, _ := b["addresses"].([]any); len(as) != 1 || as[0] != "bob@acme.example" {
		t.Fatalf("bob: %v", b["addresses"])
	}
}

// TestModules: a module off = no consumer, no service in the status, no port for keel; on
// again brings them back; a fixed module (Kanidm's) cannot be switched.
func TestModules(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	names := func(ms []any) string {
		out := ""
		for _, m := range ms {
			x := m.(map[string]any)
			out += fmt.Sprintf("%s:%v/%v ", x["name"], x["enabled"], x["fixed"])
		}
		return out
	}
	ms := r.ok("GET", "/v1/modules", nil)["modules"].([]any)
	if got := names(ms); got != "ldap:true/false oidc:true/false radius:true/false phone:false/false totp:false/false computers:false/false " {
		t.Fatalf("modules: %s", got)
	}
	st := r.ok("GET", "/v1/status", nil)
	if p := fmt.Sprint(st["ports"]); p != "[tcp/636 tcp/8443 udp/1812]" {
		t.Fatalf("ports: %s", p)
	}
	ms = r.ok("PUT", "/v1/modules/radius", map[string]any{"enabled": false})["modules"].([]any)
	if got := names(ms); got != "ldap:true/false oidc:true/false radius:false/false phone:false/false totp:false/false computers:false/false " {
		t.Fatalf("after off: %s", got)
	}
	st = r.ok("GET", "/v1/status", nil)
	if p := fmt.Sprint(st["ports"]); p != "[tcp/636 tcp/8443]" {
		t.Fatalf("ports after off: %s", p)
	}
	if _, has := st["services"].(map[string]any)["radiusd"]; has {
		t.Fatalf("radiusd still in services: %v", st["services"])
	}
	cons := r.ok("GET", "/v1/consumers", nil)["consumers"].([]any)
	for _, c := range cons {
		if c.(map[string]any)["id"] == "wifi" {
			t.Fatalf("wifi still offered: %v", cons)
		}
	}
	if code, out, _ := r.call("PUT", "/v1/consumers/wifi", "", map[string]any{"group": "wifi"}); code != 404 {
		t.Fatalf("a group for a module that is off: %d %v", code, out)
	}
	r.ok("PUT", "/v1/modules/radius", map[string]any{"enabled": true})
	st = r.ok("GET", "/v1/status", nil)
	if p := fmt.Sprint(st["ports"]); p != "[tcp/636 tcp/8443 udp/1812]" {
		t.Fatalf("ports after on: %s", p)
	}
	if code, out, _ := r.call("PUT", "/v1/modules/nope", "", map[string]any{"enabled": true}); code != 404 {
		t.Fatalf("unknown module: %d %v", code, out)
	}
	// off survives a restart (the setting is in the state)
	r.ok("PUT", "/v1/modules/ldap", map[string]any{"enabled": false})
	if r.s.State().Modules["ldap"] != false || r.s.moduleOn("ldap") {
		t.Fatal("ldap off not kept")
	}
}

// TestPhoneLogin: the phone module end to end: enrol a phone (one-time code, its key and
// signature), log in by challenge on the page and on the oidc login page, list and remove.
func TestPhoneLogin(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	if code, _, _ := r.call("POST", "/login/phone", "none", nil); code != 404 {
		t.Fatalf("module off: %d", code)
	}
	r.ok("PUT", "/v1/modules/phone", map[string]any{"enabled": true})
	if st := r.ok("GET", "/login/state", nil); st["phone"] != true {
		t.Fatalf("login state: %v", st)
	}
	origin := r.s.Origin()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// enrol (an administrator starts it for alice; alice would do it on her own page)
	e := r.ok("POST", "/v1/phones/enroll", map[string]any{"user": "alice"})
	if !strings.HasPrefix(e["qr"].(string), "data:image/svg+xml;base64,") {
		t.Fatalf("no qr: %v", e)
	}
	u, _ := url.Parse(e["url"].(string))
	code := u.Query().Get("c")
	if u.Query().Get("o") != origin || code == "" {
		t.Fatalf("enrol url %s (origin %s)", e["url"], origin)
	}
	if st := r.ok("GET", "/v1/phones/enroll/"+e["id"].(string), nil); st["state"] != "pending" {
		t.Fatalf("enrolment: %v", st)
	}
	c, out, _ := r.call("POST", "/phone/enroll", "none", map[string]any{"code": code, "name": "Alice's phone", "platform": "ios",
		"key": phone.EncodeKey(&priv.PublicKey), "sig": phone.Sign(priv, "keelauth-enroll\n"+origin+"\n"+code)})
	if c != 200 || out["user"] != "alice" {
		t.Fatalf("enrol: %d %v", c, out)
	}
	dev := out["device"].(string)
	if st := r.ok("GET", "/v1/phones/enroll/"+e["id"].(string), nil); st["state"] != "done" {
		t.Fatalf("enrolment after: %v", st)
	}
	// log in on the page
	ch := r.ok("POST", "/login/phone", nil)
	id, poll := ch["id"].(string), ch["poll"].(string)
	if st := r.ok("GET", "/login/phone/"+id+"?poll="+poll, nil); st["state"] != "pending" {
		t.Fatalf("poll: %v", st)
	}
	// the nonce is in the QR code only: read it back from the challenge
	var nonce string
	nonce = challengeNonce(r.s, id)
	msg := "keelauth-login\n" + origin + "\n" + id + "\n" + nonce
	if c, out, _ := r.call("POST", "/phone/approve", "none", map[string]any{"c": id, "n": nonce, "device": "nope", "sig": phone.Sign(priv, msg)}); c != 403 {
		t.Fatalf("unknown device: %d %v", c, out)
	}
	if c, out, _ := r.call("POST", "/phone/approve", "none", map[string]any{"c": id, "n": nonce, "device": dev, "sig": phone.Sign(priv, msg)}); c != 200 {
		t.Fatalf("approve: %d %v", c, out)
	}
	c, out, hd := r.call("GET", "/login/phone/"+id+"?poll="+poll, "none", nil)
	if c != 200 || out["state"] != "approved" || out["session"].(map[string]any)["name"] != "alice" || !strings.Contains(hd.Get("Set-Cookie"), "=") {
		t.Fatalf("approved poll: %d %v cookie %q", c, out, hd.Get("Set-Cookie"))
	}
	// the oidc login page's hooks
	d := oidcDir{r.s}
	if !d.PhoneOn() {
		t.Fatal("PhoneOn")
	}
	id2, poll2, qr2, ok := d.PhoneChallenge()
	if !ok || qr2 == "" {
		t.Fatal("PhoneChallenge")
	}
	msg2 := "keelauth-login\n" + origin + "\n" + id2 + "\n" + challengeNonce(r.s, id2)
	r.ok("POST", "/phone/approve", map[string]any{"c": id2, "n": challengeNonce(r.s, id2), "device": dev, "sig": phone.Sign(priv, msg2)})
	if st, user := d.PhonePoll(id2, poll2); st != "approved" || user != "alice" {
		t.Fatalf("PhonePoll: %s %s", st, user)
	}
	// list, last_used, remove
	ps := r.ok("GET", "/v1/phones?user=alice", nil)["phones"].([]any)
	if len(ps) != 1 || ps[0].(map[string]any)["last_used"] == "" || ps[0].(map[string]any)["name"] != "Alice's phone" {
		t.Fatalf("phones: %v", ps)
	}
	r.ok("DELETE", "/v1/phones/"+dev, nil)
	if ps := r.ok("GET", "/v1/phones?user=alice", nil)["phones"].([]any); len(ps) != 0 {
		t.Fatalf("after remove: %v", ps)
	}
	// a removed phone cannot log in
	ch3 := r.ok("POST", "/login/phone", nil)
	id3 := ch3["id"].(string)
	msg3 := "keelauth-login\n" + origin + "\n" + id3 + "\n" + challengeNonce(r.s, id3)
	if c, _, _ := r.call("POST", "/phone/approve", "none", map[string]any{"c": id3, "n": challengeNonce(r.s, id3), "device": dev, "sig": phone.Sign(priv, msg3)}); c != 403 {
		t.Fatalf("removed phone approved: %d", c)
	}
}

// challengeNonce reads a pending challenge's nonce (the phone gets it from the QR code).
func challengeNonce(s *Server, id string) string { return s.phone().Nonce(id) }

// TestTOTPLogin: the totp module: set up on the own page, asked at the login (page and the
// oidc login page's hooks), no replay, an administrator removes it.
func TestTOTPLogin(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("PUT", "/v1/modules/totp", map[string]any{"enabled": true})
	code, out, hd := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7"})
	if code != 200 {
		t.Fatalf("login: %d %v", code, out)
	}
	var sid string
	for _, c := range hd.Values("Set-Cookie") {
		if strings.HasPrefix(c, sessionCookie+"=") {
			sid = strings.SplitN(strings.TrimPrefix(c, sessionCookie+"="), ";", 2)[0]
		}
	}
	auth := "cookie:" + sid + ":" + out["csrf"].(string)
	if code, out, _ := r.call("GET", "/v1/totp", auth, nil); code != 200 || out["set"] != false || out["enabled"] != true {
		t.Fatalf("totp state: %d %v", code, out)
	}
	code, e, _ := r.call("POST", "/v1/totp/enroll", auth, map[string]any{})
	if code != 200 || !strings.HasPrefix(e["url"].(string), "otpauth://totp/") || e["qr"] == "" {
		t.Fatalf("enrol: %d %v", code, e)
	}
	secret := e["secret"].(string)
	if code, out, _ := r.call("POST", "/v1/totp/confirm", auth, map[string]any{"code": "000000"}); code != 400 {
		t.Fatalf("wrong confirm code: %d %v", code, out)
	}
	good := func() string { c, _ := totp.Code(secret, totp.Step(r.s.now())); return c }
	if code, out, _ := r.call("POST", "/v1/totp/confirm", auth, map[string]any{"code": good()}); code != 200 {
		t.Fatalf("confirm: %d %v", code, out)
	}
	// the login asks for the code now
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7"}); code != 401 || out["code"] != "totp_required" {
		t.Fatalf("no code: %d %v", code, out)
	}
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7", "code": "123456"}); code != 401 || out["code"] != "bad_code" {
		t.Fatalf("wrong code: %d %v", code, out)
	}
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7", "code": good()}); code != 200 {
		t.Fatalf("right code: %d %v", code, out)
	}
	// the same code again in the same step: replay refused
	if code, _, _ := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7", "code": good()}); code != 401 {
		t.Fatalf("replay accepted: %d", code)
	}
	// the oidc login page's hooks
	d := oidcDir{r.s}
	tok, needed := d.SecondFactor("alice")
	if !needed || tok == "" {
		t.Fatal("SecondFactor")
	}
	if _, needed := d.SecondFactor("nobody"); needed {
		t.Fatal("SecondFactor for a user without a code")
	}
	if name, ok := d.CheckSecondFactor(tok, "000000"); ok || name != "alice" {
		t.Fatalf("wrong oidc code: %s %v", name, ok)
	}
	totpMu.Lock()
	delete(totpLast, "alice") // a new step for the test
	totpMu.Unlock()
	if name, ok := d.CheckSecondFactor(tok, good()); !ok || name != "alice" {
		t.Fatalf("right oidc code: %s %v", name, ok)
	}
	if _, ok := d.CheckSecondFactor(tok, good()); ok {
		t.Fatal("token used twice")
	}
	// an administrator removes it: the password alone logs in again
	r.ok("DELETE", "/v1/totp?user=alice", nil)
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "alice", "password": "orange-kettle-7"}); code != 200 {
		t.Fatalf("after remove: %d %v", code, out)
	}
	// module off: no code asked even when set
	r.ok("PUT", "/v1/modules/totp", map[string]any{"enabled": false})
	if code, _, _ := r.call("POST", "/v1/totp/enroll", auth, map[string]any{}); code != 404 {
		t.Fatalf("enrol with the module off: %d", code)
	}
}
