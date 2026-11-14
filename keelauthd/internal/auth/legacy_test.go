package auth

import (
	"slices"
	"testing"
)

// On Kanidm, the old engine (docs/02 §9.4): LDAP and the SSO applications cannot be given a group
// (Kanidm serves them itself), and saying so is a 409, not a group stored and never applied; the
// services keelauthd serves itself (shares, Wi-Fi, sync keys) still take one. The alert says which
// engine it is.
func TestLegacyEngine(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7"})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	r.ok("POST", "/v1/oidc", map[string]any{"name": "app1", "display_name": "App 1", "landing_url": "https://app1/", "redirect_urls": []string{"https://app1/cb"}})
	if a := alertCodes(r.s.Alerts()); slices.Contains(a, "legacy_engine") {
		t.Fatalf("the test engine is not Kanidm: %v", a)
	}
	if err := r.s.update(func(st *State) error { st.Engine = EngineKanidm; return nil }, false); err != nil {
		t.Fatal(err)
	}
	if a := alertCodes(r.s.Alerts()); !slices.Contains(a, "legacy_engine") {
		t.Fatalf("no legacy_engine alert on Kanidm: %v", a)
	}
	cons := map[string]map[string]any{}
	for _, c := range r.ok("GET", "/v1/consumers", nil)["consumers"].([]any) {
		m := c.(map[string]any)
		cons[m["id"].(string)] = m
	}
	for _, id := range []string{"ldap", "oidc:app1"} {
		if cons[id] == nil || cons[id]["unlimited"] != true {
			t.Fatalf("%s on Kanidm: %v", id, cons[id])
		}
		code, out, _ := r.call("PUT", "/v1/consumers/"+id, "", map[string]any{"group": "staff"})
		if code != 409 || out["code"] != "engine_kanidm" {
			t.Fatalf("%s given a group on Kanidm: %d %v", id, code, out)
		}
		r.ok("PUT", "/v1/consumers/"+id, map[string]any{"group": ""})
	}
	if cons["smb"]["unlimited"] == true {
		t.Fatalf("smb is keelauthd's own: %v", cons["smb"])
	}
	if c := r.ok("PUT", "/v1/consumers/smb", map[string]any{"group": "samba"}); c["group"] != "samba" || c["users"] != float64(0) {
		t.Fatalf("smb on Kanidm: %v", c)
	}
	if _, err := r.s.Eng.Group("staff"); err == nil {
		t.Fatal("a refused group was made")
	}
}
