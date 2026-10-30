package auth

import (
	"encoding/json"
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

func TestAccessRights(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/oidc", map[string]any{"name": "app1", "display_name": "App 1", "landing_url": "https://app1/", "redirect_urls": []string{"https://app1/cb"}})
	key := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "nas-a"})["key"].(string)
	cons := r.ok("GET", "/v1/consumers", nil)["consumers"].([]any)
	ids := []string{}
	for _, c := range cons {
		ids = append(ids, c.(map[string]any)["id"].(string))
	}
	if len(ids) != 4 || ids[0] != "ldap" || ids[1] != "wifi" || ids[2] != "oidc:app1" || !strings.HasPrefix(ids[3], "sync:") {
		t.Fatalf("consumers: %v", ids)
	}
	// carol: LDAP only; alice: everything (no list)
	code, out, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "carol", "password": "purple-ladder-3", "access": []string{"ldap", "nope"}})
	if code != 400 {
		t.Fatalf("unknown service accepted: %d %v", code, out)
	}
	carol := r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3", "access": []string{"ldap"}})
	if a, _ := carol["access"].([]any); len(a) != 1 || a[0] != "ldap" {
		t.Fatalf("carol access: %v", carol["access"])
	}
	if a := r.ok("GET", "/v1/users/alice", nil)["access"]; a != nil {
		t.Fatalf("alice access should be null (everything): %v", a)
	}
	d := ldapDir{r.s}
	names := []string{}
	for _, p := range d.People() {
		names = append(names, p.Name)
	}
	if strings.Join(names, ",") != "alice,carol" {
		t.Fatalf("ldap people: %v", names)
	}
	if !d.CheckPassword("carol", "purple-ladder-3") {
		t.Fatal("carol may bind to LDAP")
	}
	od := oidcDir{r.s}
	if od.Allowed("carol", "app1") || !od.Allowed("alice", "app1") {
		t.Fatal("oidc access")
	}
	// Wi-Fi: carol is left out of the RADIUS users
	us, _ := r.s.Eng.Users()
	_, auth, _ := r.s.RadiusFiles(r.s.State(), us)
	if strings.Contains(auth, "carol") || !strings.Contains(auth, "alice") {
		t.Fatalf("radius users:\n%s", auth)
	}
	// the sync key sees only who may use it
	code, sy, _ := r.call("GET", "/v1/sync/accounts", "Bearer "+key, nil)
	got := []string{}
	for _, u := range sy["users"].([]any) {
		got = append(got, u.(map[string]any)["name"].(string))
	}
	if code != 200 || strings.Join(got, ",") != "alice" {
		t.Fatalf("sync users: %d %v", code, got)
	}
	// a group's rights add: staff may use the sync key and Wi-Fi
	r.ok("POST", "/v1/groups", map[string]any{"name": "staff", "members": []string{"carol"}, "access": []string{ids[3], "wifi"}})
	for _, g := range r.ok("GET", "/v1/groups", nil)["groups"].([]any) {
		if gm := g.(map[string]any); gm["name"] == "staff" && len(gm["access"].([]any)) != 2 {
			t.Fatalf("group access: %v", gm["access"])
		}
	}
	_, sy, _ = r.call("GET", "/v1/sync/accounts", "Bearer "+key, nil)
	if len(sy["users"].([]any)) != 2 {
		t.Fatalf("sync users after the group: %v", sy["users"])
	}
	_, auth, _ = r.s.RadiusFiles(r.s.State(), us)
	if !strings.Contains(auth, "carol") {
		t.Fatal("carol not in RADIUS through the group")
	}
	// taking LDAP away from carol
	r.ok("PATCH", "/v1/users/carol", map[string]any{"access": []string{}})
	if d.CheckPassword("carol", "purple-ladder-3") {
		t.Fatal("carol still binds after LDAP was taken away")
	}
	if a, _ := r.ok("GET", "/v1/users/carol", nil)["access"].([]any); len(a) != 0 {
		t.Fatalf("carol access: %v", a)
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
