package auth

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Feature modules (docs/02 §10) with the first one, the list of a person's computers: off is
// invisible, on adds the attribute to the user, its checks, the sync keys that may read it, verify,
// self status, revisions; off keeps the values until they are deleted.
func TestFeatureComputers(t *testing.T) {
	r, _ := newNativeRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7"})
	plain := "Bearer " + r.ok("POST", "/v1/sync/keys", map[string]any{"name": "nas"})["key"].(string)
	gwk := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "portal", "features": []string{"computers"}, "self_service": true})
	gw := "Bearer " + gwk["key"].(string)
	if fmt.Sprint(gwk["features"]) != "[computers]" {
		t.Fatalf("the key's features: %v", gwk)
	}
	if code, out, _ := r.call("POST", "/v1/sync/keys", "", map[string]any{"name": "x", "features": []string{"nope"}}); code != 400 {
		t.Fatalf("an unknown feature on a key: %d %v", code, out)
	}
	pcs := []map[string]any{{"name": "GYOMU90", "address": "192.168.1.50"}, {"name": "dev-box", "address": "pc1.office.lan", "port": "3390"}}
	// off: nowhere to be seen, and not settable
	if code, out, _ := r.call("PATCH", "/v1/users/alice", "", map[string]any{"features": map[string]any{"computers": pcs}}); code != 400 {
		t.Fatalf("set while off: %d %v", code, out)
	}
	if u := r.ok("GET", "/v1/users/alice", nil); u["features"] != nil {
		t.Fatalf("features while off: %v", u)
	}
	// on: the module counts as an account change for the readers
	rev := func() float64 {
		_, sy, _ := r.call("GET", "/v1/sync/accounts", gw, nil)
		return sy["revision"].(float64)
	}
	before := rev()
	r.ok("PUT", "/v1/modules/computers", map[string]any{"enabled": true})
	if rev() == before {
		t.Fatal("switching a feature module on did not bump the revision")
	}
	if u := r.ok("GET", "/v1/users/alice", nil); fmt.Sprint(u["features"]) != "map[computers:[]]" {
		t.Fatalf("on, nothing set: %v", u["features"])
	}
	before = rev()
	u := r.ok("PATCH", "/v1/users/alice", map[string]any{"features": map[string]any{"computers": pcs}})
	got, _ := json.Marshal(u["features"])
	if string(got) != `{"computers":[{"address":"192.168.1.50","name":"GYOMU90","port":3389},{"address":"pc1.office.lan","name":"dev-box","port":3390}]}` {
		t.Fatalf("set: %s", got)
	}
	if rev() == before {
		t.Fatal("a feature change did not bump the revision")
	}
	// checks: each says where; a refused value changes nothing
	for _, c := range []struct {
		rows []map[string]any
		want string
	}{
		{[]map[string]any{{"name": "A", "address": "10.0.0.1"}, {"name": "a", "address": "10.0.0.2"}}, "row 2: name: a is already in the list"},
		{[]map[string]any{{"name": "A", "address": "300.1.1.1"}}, "row 1: address: not an IPv4"},
		{[]map[string]any{{"name": "A", "address": "bad host!"}}, "row 1: address: not an IPv4"},
		{[]map[string]any{{"name": "A", "address": "10.0.0.1", "port": 70000}}, "row 1: port: 1 to 65535"},
		{[]map[string]any{{"name": "A B", "address": "10.0.0.1"}}, "row 1: name: only letters"},
		{[]map[string]any{{"address": "10.0.0.1"}}, "row 1: name: required"},
		{[]map[string]any{{"name": "A", "address": "10.0.0.1", "user": "x"}}, "row 1: user: no such field"},
		{[]map[string]any{{"name": strings.Repeat("x", 33), "address": "10.0.0.1"}}, "row 1: name: at most 32"},
	} {
		code, out, _ := r.call("PATCH", "/v1/users/alice", "", map[string]any{"features": map[string]any{"computers": c.rows}, "display_name": "Changed"})
		if code != 400 || !strings.Contains(fmt.Sprint(out["error"]), c.want) {
			t.Fatalf("%v: %d %v (want %q)", c.rows, code, out, c.want)
		}
	}
	if u := r.ok("GET", "/v1/users/alice", nil); u["display_name"] == "Changed" || len(u["features"].(map[string]any)["computers"].([]any)) != 2 {
		t.Fatalf("a refused change left something: %v", u)
	}
	// a new user with computers; a bad list makes no user
	if code, _, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "bob", "password": "purple-ladder-3", "features": map[string]any{"computers": []map[string]any{{"name": "x"}}}}); code != 400 {
		t.Fatal("a user made with a bad computer list")
	}
	if code, _, _ := r.call("GET", "/v1/users/bob", "", nil); code != 404 {
		t.Fatal("half-made bob")
	}
	r.ok("POST", "/v1/users", map[string]any{"name": "bob", "password": "purple-ladder-3", "features": map[string]any{"computers": []map[string]any{{"name": "B1", "address": "10.0.0.9", "port": 3390}}}})
	// the sync: only keys that read the module see it
	accounts := func(key string) map[string]map[string]any {
		_, sy, _ := r.call("GET", "/v1/sync/accounts", key, nil)
		out := map[string]map[string]any{}
		for _, u := range sy["users"].([]any) {
			out[u.(map[string]any)["name"].(string)] = u.(map[string]any)
		}
		return out
	}
	if a := accounts(plain)["alice"]; a["features"] != nil {
		t.Fatalf("a key without the module sees it: %v", a)
	}
	if a := accounts(gw); len(a["alice"]["features"].(map[string]any)["computers"].([]any)) != 2 || len(a["bob"]["features"].(map[string]any)["computers"].([]any)) != 1 {
		t.Fatalf("the gateway's sync: %v", a)
	}
	// verify and the self status carry it; computers are not the person's to change
	code, v, _ := r.call("POST", "/v1/sync/verify", gw, map[string]any{"name": "alice", "password": "orange-kettle-7"})
	if code != 200 || len(v["features"].(map[string]any)["computers"].([]any)) != 2 {
		t.Fatalf("verify: %d %v", code, v)
	}
	if code, v, _ := r.call("POST", "/v1/sync/verify", plain, map[string]any{"name": "alice", "password": "orange-kettle-7"}); code != 200 || v["features"] != nil {
		t.Fatalf("verify with a key without the module: %d %v", code, v)
	}
	if _, st, _ := r.call("POST", "/v1/sync/self", gw, map[string]any{"name": "alice", "password": "orange-kettle-7"}); st["features"] == nil {
		t.Fatalf("self status without features: %v", st)
	}
	if code, out, _ := r.call("POST", "/v1/sync/self/features", gw, map[string]any{"name": "alice", "password": "orange-kettle-7", "features": map[string]any{"computers": []any{}}}); code != 403 || out["code"] != "not_self_edit" {
		t.Fatalf("self edit of computers: %d %v", code, out)
	}
	// off: gone from everything, kept; delete only while off; on again: what is left
	if code, _, _ := r.call("DELETE", "/v1/features/computers/data", "", nil); code != 409 {
		t.Fatal("data deleted while on")
	}
	r.ok("PUT", "/v1/modules/computers", map[string]any{"enabled": false})
	if a := accounts(gw)["alice"]; a["features"] != nil {
		t.Fatalf("off, still in the sync: %v", a)
	}
	fs := r.ok("GET", "/v1/features", nil)["features"].([]any)[0].(map[string]any)
	if fs["enabled"] != false || fs["users_with_data"] != float64(2) {
		t.Fatalf("features list while off: %v", fs)
	}
	if out := r.ok("DELETE", "/v1/features/computers/data", nil); out["removed"] != float64(2) {
		t.Fatalf("delete: %v", out)
	}
	r.ok("PUT", "/v1/modules/computers", map[string]any{"enabled": true})
	if u := r.ok("GET", "/v1/users/alice", nil); fmt.Sprint(u["features"]) != "map[computers:[]]" {
		t.Fatalf("after delete: %v", u["features"])
	}
}
