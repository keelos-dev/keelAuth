package auth

import (
	"strings"
	"testing"
	"time"

	"keelauth/internal/module/totp"
)

// An employee's own business through a front end (docs/02 §9.5): a new person at home with an
// initial password and no authenticator sets both up through a self_service key and only then
// gets through verify; the wrong tries count with verify's; an old initial password is refused;
// keelAuth's page can be left to administrators.
func TestSelfService(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("PUT", "/v1/modules/totp", map[string]any{"enabled": true})
	r.ok("POST", "/v1/users", map[string]any{"name": "erin", "password": "first-pass-1234", "must_change": true})
	r.ok("POST", "/v1/users", map[string]any{"name": "frank", "password": "frank-pass-1234", "must_change": true})
	fresh := func() { totpMu.Lock(); delete(totpLast, "erin"); totpMu.Unlock() }
	fresh()
	t.Cleanup(fresh)
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "portal", "group": "telework", "secrets": false, "require_totp": true, "self_service": true})
	if k["self_service"] != true {
		t.Fatalf("the key: %v", k)
	}
	key := "Bearer " + k["key"].(string)
	plain := "Bearer " + r.ok("POST", "/v1/sync/keys", map[string]any{"name": "nas"})["key"].(string)
	r.ok("PATCH", "/v1/groups/telework", map[string]any{"members": []string{"erin", "frank"}})
	call := func(auth, path string, body map[string]any) (int, map[string]any) {
		c, out, _ := r.call("POST", path, auth, body)
		return c, out
	}
	pw := "first-pass-1234"
	me := func(extra map[string]any) map[string]any {
		b := map[string]any{"name": "erin", "password": pw}
		for k, v := range extra {
			b[k] = v
		}
		return b
	}
	// only a key with self_service
	if c, out := call(plain, "/v1/sync/self", me(nil)); c != 403 || out["code"] != "not_self_service" {
		t.Fatalf("a key without self_service: %d %v", c, out)
	}
	// not finished: verify says so; the status says what is missing
	if c, out := call(key, "/v1/sync/verify", me(nil)); c != 403 || out["code"] != "setup_needed" {
		t.Fatalf("verify before setting up: %d %v", c, out)
	}
	c, st := call(key, "/v1/sync/self", me(nil))
	if c != 200 || strings.Join(toStrings(st["needs"]), ",") != "password,totp" || st["totp"] != false || st["must_change"] != true || st["password_rules"] == nil {
		t.Fatalf("status: %d %v", c, st)
	}
	// the password: a weak one is refused with the reason, then a good one
	if c, out := call(key, "/v1/sync/self/password", me(map[string]any{"new_password": "abc"})); c != 400 || out["code"] != "weak_password" || out["error"] == "" {
		t.Fatalf("weak password: %d %v", c, out)
	}
	if c, out := call(key, "/v1/sync/self/password", me(map[string]any{"new_password": pw})); c != 400 || out["code"] != "weak_password" {
		t.Fatalf("the same password: %d %v", c, out)
	}
	c, st = call(key, "/v1/sync/self/password", me(map[string]any{"new_password": "garden-lamp-2026"}))
	if c != 200 || st["must_change"] != false || strings.Join(toStrings(st["needs"]), ",") != "totp" {
		t.Fatalf("password changed: %d %v", c, st)
	}
	if c, out := call(key, "/v1/sync/self", me(nil)); c != 401 || out["code"] != "bad_login" {
		t.Fatalf("the old password after the change: %d %v", c, out)
	}
	pw = "garden-lamp-2026"
	// the authenticator: started, a wrong code from it, the right one
	c, en := call(key, "/v1/sync/self/totp", me(nil))
	if c != 200 || en["secret"] == nil || !strings.HasPrefix(en["url"].(string), "otpauth://") {
		t.Fatalf("totp start: %d %v", c, en)
	}
	secret := en["secret"].(string)
	good := func() string { c, _ := totp.Code(secret, totp.Step(r.s.now())); return c }
	if c, out := call(key, "/v1/sync/self/totp/confirm", me(map[string]any{"new_code": "000000"})); c != 400 || out["code"] != "bad_new_code" {
		t.Fatalf("wrong new code: %d %v", c, out)
	}
	c, st = call(key, "/v1/sync/self/totp/confirm", me(map[string]any{"new_code": good()}))
	if c != 200 || st["totp"] != true || st["totp_set_at"] == "" || len(toStrings(st["needs"])) != 0 {
		t.Fatalf("totp confirmed: %d %v", c, st)
	}
	// from now on the code is part of every proof, and verify lets erin in
	if c, out := call(key, "/v1/sync/self", me(nil)); c != 401 || out["code"] != "totp_required" {
		t.Fatalf("status without the code: %d %v", c, out)
	}
	if c, out := call(key, "/v1/sync/verify", me(map[string]any{"code": good()})); c != 200 || out["name"] != "erin" {
		t.Fatalf("verify after setting up: %d %v", c, out)
	}
	// one counter for verify and these calls: five wrong tries in all, then a wait
	for i := 0; i < 5; i++ {
		path := "/v1/sync/verify"
		if i%2 == 1 {
			path = "/v1/sync/self"
		}
		call(key, path, map[string]any{"name": "erin", "password": "wrong-" + path})
	}
	if c, out := call(key, "/v1/sync/self", me(nil)); c != 429 || out["code"] != "too_many" {
		t.Fatalf("after five wrong tries across verify and self: %d %v", c, out)
	}
	// an initial password older than 14 days opens nothing from outside
	r.s.update(func(st *State) error {
		st.user("frank").SetAt = r.s.now().Add(-15 * 24 * time.Hour).Format(time.RFC3339)
		return nil
	}, false)
	fr := map[string]any{"name": "frank", "password": "frank-pass-1234"}
	if c, out := call(key, "/v1/sync/self", fr); c != 403 || out["code"] != "password_expired" {
		t.Fatalf("an old initial password, self: %d %v", c, out)
	}
	if c, out := call(plain, "/v1/sync/verify", fr); c != 403 || out["code"] != "password_expired" {
		t.Fatalf("an old initial password, verify with any key: %d %v", c, out)
	}
	// keelAuth's page for administrators only: frank (reset by the admin) logs in and may not change anything there
	r.ok("POST", "/v1/users/frank/password", map[string]any{"password": "frank-pass-5678", "must_change": false})
	set := r.ok("PUT", "/v1/settings", map[string]any{"self_service_where": "app", "self_service_note": "CSTclient で変更してください"})
	if set["self_service_where"] != "app" {
		t.Fatalf("settings: %v", set)
	}
	code, out, hd := r.call("POST", "/login", "none", map[string]any{"name": "frank", "password": "frank-pass-5678"})
	if code != 200 || out["self_service_where"] != "app" || out["self_service_note"] != "CSTclient で変更してください" {
		t.Fatalf("frank's login: %d %v", code, out)
	}
	var sid string
	for _, c := range hd.Values("Set-Cookie") {
		if strings.HasPrefix(c, sessionCookie+"=") {
			sid = strings.SplitN(strings.TrimPrefix(c, sessionCookie+"="), ";", 2)[0]
		}
	}
	page := "cookie:" + sid + ":" + out["csrf"].(string)
	for _, p := range []string{"/password", "/v1/totp/enroll", "/v1/phones/enroll"} {
		if c, out, _ := r.call("POST", p, page, map[string]any{"old": "frank-pass-5678", "new": "frank-pass-9999"}); c != 403 || out["code"] != "elsewhere" {
			if !(p == "/v1/phones/enroll" && c == 404) { // the phone module is off here
				t.Fatalf("%s on the page in app mode: %d %v", p, c, out)
			}
		}
	}
	// back to the page: frank may change his password there again
	r.ok("PUT", "/v1/settings", map[string]any{"self_service_where": "page"})
	if c, out, _ := r.call("POST", "/password", page, map[string]any{"old": "frank-pass-5678", "new": "frank-pass-9999"}); c != 200 {
		t.Fatalf("own password on the page again: %d %v", c, out)
	}
}

func toStrings(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}
