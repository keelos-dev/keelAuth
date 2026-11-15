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

// The employee and names modules (docs/02 §10.4, docs/05 §1.9): a number that is nobody else's
// and of the length the admin fixed, an employment type out of the admin's options, names and
// their readings; finding people by them; LDAP attributes for the devices that may read them.
func TestFeatureEmployee(t *testing.T) {
	r, _ := newNativeRig(t)
	for _, n := range []string{"alice", "bob", "carol"} {
		r.ok("POST", "/v1/users", map[string]any{"name": n, "password": "orange-kettle-7"})
	}
	r.ok("PUT", "/v1/modules/employee", map[string]any{"enabled": true})
	r.ok("PUT", "/v1/modules/names", map[string]any{"enabled": true})
	set := func(user string, v map[string]any) (int, string) {
		code, out, _ := r.call("PATCH", "/v1/users/"+user, "", map[string]any{"features": v})
		return code, fmt.Sprint(out["error"])
	}
	emp := func(v map[string]any) map[string]any { return map[string]any{"employee": v} }
	if code, msg := set("alice", emp(map[string]any{"employeeType": "regular"})); code != 400 || !strings.Contains(msg, "no options yet") {
		t.Fatalf("a type before there are options: %d %s", code, msg)
	}
	opt := func(code, zh string) map[string]any {
		return map[string]any{"code": code, "title": map[string]any{"zh": zh}}
	}
	four := []any{opt("regular", "正式员工"), opt("contract", "合同工"), opt("proprietor", "个体经营者"), opt("external", "外部")}
	conf := r.ok("PUT", "/v1/features/employee/conf", map[string]any{"options": map[string]any{"employeeType": four}, "len": map[string]any{"employeeNumber": 5}})
	if got, _ := json.Marshal(conf["conf"]); !strings.Contains(string(got), `"employeeNumber":5`) || !strings.Contains(string(got), `{"code":"external","title":{"zh":"外部"}}`) {
		t.Fatalf("conf: %s", got)
	}
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"options": map[string]any{"employeeNumber": four}}, "not a choice field"},
		{map[string]any{"options": map[string]any{"employeeType": []any{opt("Regular", "x")}}}, "the code"},
		{map[string]any{"options": map[string]any{"employeeType": []any{opt("a", "x"), opt("a", "y")}}}, "twice"},
		{map[string]any{"len": map[string]any{"employeeType": 3}}, "no length"},
		{map[string]any{"len": map[string]any{"employeeNumber": 99}}, "a length from"},
	} {
		if code, out, _ := r.call("PUT", "/v1/features/employee/conf", "", c.body); code != 400 || !strings.Contains(fmt.Sprint(out["error"]), c.want) {
			t.Fatalf("%v: %d %v", c.body, code, out)
		}
	}
	if code, msg := set("alice", map[string]any{"employee": map[string]any{"employeeNumber": "11011", "employeeType": "regular"},
		"names": map[string]any{"sn": "山田", "givenName": "太郎", "phoneticLastName": "ヤマダ", "phoneticFirstName": "タロウ"}}); code != 200 {
		t.Fatalf("alice: %d %s", code, msg)
	}
	for _, c := range []struct {
		v    map[string]any
		want string
	}{
		{map[string]any{"employeeNumber": "11011"}, "employeeNumber: 11011 is already alice's"},
		{map[string]any{"employeeNumber": "1234"}, "employeeNumber: exactly 5 characters"},
		{map[string]any{"employeeNumber": "12a45"}, "employeeNumber: only digits"},
		{map[string]any{"employeeType": "boss"}, `"boss" is not one of regular, contract, proprietor, external`},
		{map[string]any{"title": "x"}, "title: no such field"},
	} {
		if code, msg := set("bob", emp(c.v)); code != 400 || !strings.Contains(msg, c.want) {
			t.Fatalf("%v: %d %s (want %q)", c.v, code, msg, c.want)
		}
	}
	if code, out, _ := r.call("POST", "/v1/users", "", map[string]any{"name": "dave", "password": "purple-ladder-3", "features": emp(map[string]any{"employeeNumber": "11011"})}); code != 400 {
		t.Fatalf("a new user with a taken number: %d %v", code, out)
	}
	if code, _, _ := r.call("GET", "/v1/users/dave", "", nil); code != 404 {
		t.Fatal("half-made dave")
	}
	// alice may keep her own number; bob gets another; carol is borrowed staff: a type, no number
	if code, msg := set("alice", emp(map[string]any{"employeeNumber": "11011", "employeeType": "contract"})); code != 200 {
		t.Fatalf("alice again: %d %s", code, msg)
	}
	if code, msg := set("bob", emp(map[string]any{"employeeNumber": "22022", "employeeType": "regular"})); code != 200 {
		t.Fatalf("bob: %d %s", code, msg)
	}
	if code, msg := set("carol", emp(map[string]any{"employeeType": "external", "employeeNumber": ""})); code != 200 {
		t.Fatalf("carol: %d %s", code, msg)
	}
	if u := r.ok("GET", "/v1/users/carol", nil); fmt.Sprint(u["features"]) != "map[employee:map[employeeType:external] names:map[]]" {
		t.Fatalf("carol: %v", u["features"])
	}
	// finding people
	names := func(query string) string {
		out := []string{}
		for _, u := range r.ok("GET", "/v1/users?"+query, nil)["users"].([]any) {
			out = append(out, u.(map[string]any)["name"].(string))
		}
		return strings.Join(out, ",")
	}
	for q, want := range map[string]string{"employeeNumber=11011": "alice", "employeeType=external": "carol", "employeeType=regular": "bob",
		"q=22": "bob", "q=%E3%83%A4%E3%83%9E%E3%83%80": "alice", "employeeNumber=": "carol", "q=a&employeeType=contract": "alice", "q=zzz": ""} {
		if got := names(q); got != want {
			t.Fatalf("?%s: %q, want %q", q, got, want)
		}
	}
	if code, _, _ := r.call("GET", "/v1/users?shoeSize=42", "", nil); code != 400 {
		t.Fatal("an unknown filter")
	}
	// the settings cannot strand values
	rest := []any{opt("regular", "正式员工"), opt("contract", "合同工"), opt("proprietor", "个体经营者")}
	if code, out, _ := r.call("PUT", "/v1/features/employee/conf", "", map[string]any{"options": map[string]any{"employeeType": rest}}); code != 409 ||
		!strings.Contains(fmt.Sprint(out["error"]), "external is still used by 1 accounts (carol)") {
		t.Fatalf("an option in use removed: %d %v", code, out)
	}
	if code, out, _ := r.call("PUT", "/v1/features/employee/conf", "", map[string]any{"len": map[string]any{"employeeNumber": 4}}); code != 409 ||
		!strings.Contains(fmt.Sprint(out["error"]), "2 accounts") {
		t.Fatalf("a length the numbers do not have: %d %v", code, out)
	}
	r.ok("PUT", "/v1/features/employee/conf", map[string]any{"options": map[string]any{"employeeType": []any{four[0], four[1], four[3]}}}) // proprietor: nobody's
	// LDAP: by module, for the devices that read it
	dev := r.ok("POST", "/v1/ldap/devices", map[string]any{"name": "hr-app", "features": []string{"employee"}})
	if fmt.Sprint(dev["features"]) != "[employee]" || fmt.Sprint(ldapDir{r.s}.Reads("hr-app")) != "[employee]" {
		t.Fatalf("the device: %v", dev)
	}
	if code, _, _ := r.call("PATCH", "/v1/ldap/devices/hr-app", "", map[string]any{"features": []string{"nope"}}); code != 400 {
		t.Fatal("an unknown module on a device")
	}
	if dev = r.ok("PATCH", "/v1/ldap/devices/hr-app", map[string]any{"features": []string{"employee", "names"}}); fmt.Sprint(dev["features"]) != "[employee names]" {
		t.Fatalf("the device after the change: %v", dev)
	}
	extra := func(user string) string {
		for _, p := range (ldapDir{r.s}).People() {
			if p.Name == user {
				return fmt.Sprint(p.Extra)
			}
		}
		return "no " + user
	}
	if got, want := extra("alice"), "[{employee [inetOrgPerson] [{employeeNumber [11011]} {employeeType [contract]}]} "+
		"{names [inetOrgPerson] [{sn [山田]} {givenName [太郎]} {msDS-PhoneticLastName [ヤマダ]} {msDS-PhoneticFirstName [タロウ]} {msDS-PhoneticDisplayName [ヤマダ タロウ]}]}]"; got != want {
		t.Fatalf("alice in LDAP:\n%s\nwant\n%s", got, want)
	}
	r.ok("PUT", "/v1/modules/names", map[string]any{"enabled": false})
	if got := extra("alice"); strings.Contains(got, "names") || !strings.Contains(got, "employeeNumber") {
		t.Fatalf("names off: %s", got)
	}
	// every field emptied = no value; a deleted account's number is free again
	set("bob", emp(map[string]any{"employeeNumber": "", "employeeType": ""}))
	r.ok("DELETE", "/v1/users/alice", nil)
	if code, msg := set("bob", emp(map[string]any{"employeeNumber": "11011"})); code != 200 {
		t.Fatalf("a freed number: %d %s", code, msg)
	}
	for _, f := range r.ok("GET", "/v1/features", nil)["features"].([]any) {
		if m := f.(map[string]any); m["name"] == "employee" && m["users_with_data"] != float64(2) {
			t.Fatalf("accounts with values: %v", m["users_with_data"])
		}
	}
}
