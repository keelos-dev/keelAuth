package auth

import (
	"fmt"
	"strings"
	"testing"
)

// Account names with dots (first.last, docs/02 §11): the rule, and the places a name goes:
// the page login, LDAP, the RADIUS users file, the sync and verify, mail addresses.
func TestDottedNames(t *testing.T) {
	for n, want := range map[string]bool{"manho.sen": true, "a.b.c": true, "a-b.c_d": true, "anna": true,
		".anna": false, "anna.": false, "an..na": false, "Manho.sen": false, "1a.b": false, "a.1": true,
		strings.Repeat("a", 30) + ".b": true, strings.Repeat("a", 31) + ".b": false} {
		if ValidUserName(n) != want {
			t.Errorf("ValidUserName(%q) = %v", n, !want)
		}
	}
	if ValidName("a.b") {
		t.Error("groups took a dot")
	}
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "manho.sen", "password": "orange-kettle-7"})
	for _, bad := range []string{"manho..sen", "manho.", ".manho"} {
		if code, _, _ := r.call("POST", "/v1/users", "", map[string]any{"name": bad, "password": "orange-kettle-7"}); code != 400 {
			t.Errorf("%q made: %d", bad, code)
		}
	}
	if code, _, _ := r.call("POST", "/v1/groups", "", map[string]any{"name": "a.b"}); code != 400 {
		t.Error("a group with a dot")
	}
	// the page
	if code, out, _ := r.call("POST", "/login", "none", map[string]any{"name": "manho.sen", "password": "orange-kettle-7"}); code != 200 || out["name"] != "manho.sen" {
		t.Fatalf("login: %d %v", code, out)
	}
	if u := r.ok("GET", "/v1/users/manho.sen", nil); u["name"] != "manho.sen" {
		t.Fatalf("GET by path: %v", u)
	}
	// LDAP (keelauthd's own directory)
	d := ldapDir{r.s}
	if !d.CheckPassword("manho.sen", "orange-kettle-7") {
		t.Fatal("LDAP bind")
	}
	// RADIUS: the users file names it in quotes
	r.ok("PUT", "/v1/modules/radius", map[string]any{"enabled": true})
	r.ok("PATCH", "/v1/users/manho.sen", map[string]any{"display_name": "Manho Sen"})
	if a := r.authorize(); !strings.Contains(a, "\"manho.sen\"\tNT-Password := 0x") {
		t.Fatalf("authorize:\n%s", a)
	}
	// sync, verify, mail: the mail server's group gives manho.sen@acme.example
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1", "group": "mail"})
	key := "Bearer " + k["key"].(string)
	r.call("PUT", "/v1/sync/offers", key, map[string]any{"mail_domains": []string{"acme.example"}})
	r.ok("PATCH", "/v1/groups/mail", map[string]any{"members": []string{"manho.sen"}})
	_, sy, _ := r.call("GET", "/v1/sync/accounts", key, nil)
	us := sy["users"].([]any)
	if len(us) != 1 || us[0].(map[string]any)["name"] != "manho.sen" || fmt.Sprint(us[0].(map[string]any)["addresses"]) != "[manho.sen@acme.example]" {
		t.Fatalf("sync: %v", us)
	}
	if code, v, _ := r.call("POST", "/v1/sync/verify", key, map[string]any{"name": "manho.sen", "password": "orange-kettle-7"}); code != 200 || v["name"] != "manho.sen" {
		t.Fatalf("verify: %d %v", code, v)
	}
}
