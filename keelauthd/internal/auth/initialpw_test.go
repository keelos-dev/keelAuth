package auth

import "testing"

// A new initial password for the ticked accounts that still wait on their first change; an
// account whose owner has a password of their own is left alone (docs/07 section 1).
func TestInitialPasswords(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "anna", "display_name": "Anna"})                                                    // made, must change
	r.ok("POST", "/v1/users", map[string]any{"name": "ben", "password": "Ben-Picks-2026", "must_change": false})                         // has their own
	r.ok("POST", "/v1/users", map[string]any{"name": "cho", "display_name": "長 花子", "password": "Keel-First-2026", "must_change": true}) // typed by the administrator
	o := r.ok("POST", "/v1/passwords/initial", map[string]any{"names": []string{"anna", "ben", "cho", "nobody"}})
	made, skipped := o["made"].([]any), o["skipped"].([]any)
	if len(made) != 2 || len(skipped) != 2 || skipped[0] != "ben" || skipped[1] != "nobody" {
		t.Fatalf("made %v, skipped %v", made, skipped)
	}
	for _, m := range made {
		m := m.(map[string]any)
		name, pw := m["name"].(string), m["password"].(string)
		if ok, _ := r.eng.CheckPassword(name, pw); !ok || pw == "" || pw == "Keel-First-2026" {
			t.Errorf("%s: the new password does not log in", name)
		}
		if !r.s.State().Users[name].MustChange {
			t.Errorf("%s: no longer has to change it", name)
		}
	}
	if made[1].(map[string]any)["display_name"] != "長 花子" {
		t.Errorf("the table has no names: %v", made[1])
	}
	if ok, _ := r.eng.CheckPassword("ben", "Ben-Picks-2026"); !ok {
		t.Error("ben's own password was touched")
	}
	names := make([]string, 51)
	if code, _, _ := r.call("POST", "/v1/passwords/initial", "", map[string]any{"names": names}); code != 400 {
		t.Errorf("51 names: %d", code)
	}
}
