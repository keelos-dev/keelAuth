package auth

import (
	"slices"
	"testing"
)

// docs/05 §1.10: a service nobody chose a group for is closed; "every account" is a choice;
// a mail server open to all gives every account its mailboxes; an account's services are
// listed; an LDAP device account can stand for another service; an older state keeps what
// was open.

func consumerOf(t *testing.T, r *rig, id string) map[string]any {
	t.Helper()
	for _, c := range r.ok("GET", "/v1/consumers", nil)["consumers"].([]any) {
		if m := c.(map[string]any); m["id"] == id {
			return m
		}
	}
	t.Fatalf("no service %s", id)
	return nil
}

func servicesOfUser(r *rig, name string) map[string]string {
	out := map[string]string{}
	for _, x := range r.ok("GET", "/v1/users/"+name, nil)["services"].([]any) {
		m := x.(map[string]any)
		out[m["id"].(string)] = m["via"].(string)
	}
	return out
}

func names(ps []any) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.(map[string]any)["name"].(string))
	}
	slices.Sort(out)
	return out
}

func TestClosedByDefault(t *testing.T) {
	r, _ := newNativeRig(t)
	r.s.openUnbound = false
	if !r.s.State().ClosedDefault {
		t.Fatalf("a new state is not marked closed by default")
	}
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	// nothing was chosen: nobody has anything
	for _, id := range []string{AccessSMB, AccessLDAP, AccessWiFi} {
		if c := consumerOf(t, r, id); c["scope"] != "none" || c["users"] != 0.0 || c["group"] != "" {
			t.Fatalf("%s on a new keelAuth: %v", id, c)
		}
	}
	if ps := (ldapDir{r.s}).People(); len(ps) != 0 {
		t.Fatalf("LDAP people with nothing chosen: %v", ps)
	}
	if (ldapDir{r.s}).CheckPassword("carol", "purple-ladder-3") {
		t.Fatalf("carol binds without having LDAP")
	}
	if sv := servicesOfUser(r, "carol"); len(sv) != 0 {
		t.Fatalf("carol's services with nothing chosen: %v", sv)
	}
	// a new sync key serves nobody
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "gateway"})
	gw, gwID := "Bearer "+k["key"].(string), "sync:"+k["id"].(string)
	if _, sy, _ := r.call("GET", "/v1/sync/accounts", gw, nil); len(sy["users"].([]any)) != 0 {
		t.Fatalf("a new sync key's accounts: %v", sy["users"])
	}
	if code, m, _ := r.call("POST", "/v1/sync/verify", gw, map[string]any{"name": "carol", "password": "purple-ladder-3"}); code != 403 || m["code"] != "not_allowed" {
		t.Fatalf("verify through a key nobody was given: %d %v", code, m)
	}
	// every account, as a choice; shown; reminded of
	if c := r.ok("PUT", "/v1/consumers/"+gwID, map[string]any{"all": true}); c["scope"] != "all" || c["users"] != 2.0 || c["group"] != "" {
		t.Fatalf("opened to all: %v", c)
	}
	if code, _, _ := r.call("PUT", "/v1/consumers/"+gwID, "", map[string]any{"all": true, "group": "x"}); code != 400 {
		t.Fatalf("all and a group: %d", code)
	}
	if open := r.ok("GET", "/v1/status", nil)["open_services"].([]any); len(open) != 1 || open[0] != gwID {
		t.Fatalf("open services: %v", open)
	}
	if _, sy, _ := r.call("GET", "/v1/sync/accounts", gw, nil); len(sy["users"].([]any)) != 2 {
		t.Fatalf("an open key's accounts: %v", sy["users"])
	}
	for _, l := range r.ok("GET", "/v1/sync/keys", nil)["keys"].([]any) {
		if m := l.(map[string]any); m["all"] != true || m["group"] != nil {
			t.Fatalf("the key in the list: %v", m)
		}
	}
	// {"group": ""} closes (it opened before 2026-11-15)
	if c := r.ok("PUT", "/v1/consumers/"+gwID, map[string]any{"group": ""}); c["scope"] != "none" || c["users"] != 0.0 {
		t.Fatalf("closed again: %v", c)
	}
	// a key made open, a key made for a group
	k2 := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "everybody", "all": true})
	if c := consumerOf(t, r, "sync:"+k2["id"].(string)); k2["all"] != true || c["scope"] != "all" {
		t.Fatalf("a key made open: %v %v", k2, c)
	}
	if code, _, _ := r.call("POST", "/v1/sync/keys", "", map[string]any{"name": "x", "all": true, "group": "g"}); code != 400 {
		t.Fatalf("a key with all and a group: %d", code)
	}
	// a group gives: the account's list says through which
	r.ok("PUT", "/v1/consumers/"+AccessSMB, map[string]any{"group": "samba"})
	r.ok("PATCH", "/v1/groups/samba", map[string]any{"members": []string{"alice"}})
	if sv := servicesOfUser(r, "alice"); sv[AccessSMB] != "samba" || sv["sync:"+k2["id"].(string)] != "*" || len(sv) != 2 {
		t.Fatalf("alice's services: %v", sv)
	}
	if sv := servicesOfUser(r, "carol"); len(sv) != 1 {
		t.Fatalf("carol's services: %v", sv)
	}
	for _, u := range r.ok("GET", "/v1/users", nil)["users"].([]any) {
		if m := u.(map[string]any); m["services"] == nil {
			t.Fatalf("the list lacks services: %v", m)
		}
	}
}

func TestMailForEveryAccount(t *testing.T) {
	r, _ := newNativeRig(t)
	r.s.openUnbound = false
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "carol", "password": "purple-ladder-3"})
	r.ok("POST", "/v1/users", map[string]any{"name": "dave", "password": "silver-window-9"})
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})
	key, id := "Bearer "+k["key"].(string), "sync:"+k["id"].(string)
	r.call("PUT", "/v1/sync/offers", key, map[string]any{"mail_domains": []string{"acme.example", "other.example"}})
	// no group: by tick, and the mail server is told of the ticked accounts only
	if c := consumerOf(t, r, id); c["scope"] != "ticks" || c["users"] != 0.0 {
		t.Fatalf("a mail server without a group: %v", c)
	}
	r.ok("PATCH", "/v1/users/carol", map[string]any{"mail_domains": []string{"acme.example"}})
	_, sy, _ := r.call("GET", "/v1/sync/accounts", key, nil)
	if us := sy["users"].([]any); len(us) != 1 || us[0].(map[string]any)["name"] != "carol" || len(us[0].(map[string]any)["addresses"].([]any)) != 1 {
		t.Fatalf("the ticked accounts: %v", sy["users"])
	}
	if sv := servicesOfUser(r, "carol"); sv[id] != "tick" {
		t.Fatalf("carol's mail by tick: %v", sv)
	}
	// every account: all have every domain, a new account at once; no reminder for mail
	if c := r.ok("PUT", "/v1/consumers/"+id, map[string]any{"all": true}); c["scope"] != "all" || c["users"] != 3.0 {
		t.Fatalf("mail for every account: %v", c)
	}
	if td := r.ok("GET", "/v1/consumers", nil)["mail_domains_ticked"].([]any); len(td) != 0 {
		t.Fatalf("domains to tick when mail is everybody's: %v", td)
	}
	if as := r.ok("GET", "/v1/users/dave", nil)["addresses"].([]any); len(as) != 2 || as[0] != "dave@acme.example" {
		t.Fatalf("dave's addresses: %v", as)
	}
	nu := r.ok("POST", "/v1/users", map[string]any{"name": "erin", "password": "copper-garden-5"})
	if as := nu["addresses"].([]any); len(as) != 2 {
		t.Fatalf("a new account's addresses: %v", nu)
	}
	if sv := servicesOfUser(r, "erin"); len(sv) != 1 || sv[id] != "*" {
		t.Fatalf("a new account has mail and nothing else: %v", sv)
	}
	if open := r.ok("GET", "/v1/status", nil)["open_services"].([]any); len(open) != 0 {
		t.Fatalf("mail open to all is no reminder: %v", open)
	}
	_, sy, _ = r.call("GET", "/v1/sync/accounts", key, nil)
	if us := sy["users"].([]any); len(us) != 4 {
		t.Fatalf("the mail server's accounts: %v", names(us))
	}

	// a mail server that checks passwords over LDAP: its own device account finds the mail
	// server's people, whoever has LDAP or not
	d := ldapDir{r.s}
	r.ok("PUT", "/v1/consumers/"+id, map[string]any{"group": "mail"})
	r.ok("PATCH", "/v1/groups/mail", map[string]any{"members": []string{"carol"}})
	r.ok("PUT", "/v1/consumers/"+AccessLDAP, map[string]any{"group": "ldap"})
	r.ok("PATCH", "/v1/groups/ldap", map[string]any{"members": []string{"alice"}})
	if d.CheckPassword("carol", "purple-ladder-3") {
		t.Fatalf("carol binds before any device stands for mail")
	}
	if code, _, _ := r.call("POST", "/v1/ldap/devices", "", map[string]any{"name": "nosuch", "service": "sync:zzzz"}); code != 400 {
		t.Fatalf("a device for a service there is not: %d", code)
	}
	dev := r.ok("POST", "/v1/ldap/devices", map[string]any{"name": "mailsrv", "service": id})
	if dev["service"] != id {
		t.Fatalf("the device: %v", dev)
	}
	r.ok("POST", "/v1/ldap/devices", map[string]any{"name": "printer"})
	seen := func(bound string) []string {
		out := []string{}
		for _, p := range d.PeopleSeenBy(bound) {
			out = append(out, p.Name)
		}
		slices.Sort(out)
		return out
	}
	if got := seen("device:mailsrv"); !slices.Equal(got, []string{"carol"}) {
		t.Fatalf("the mail server's device finds %v", got)
	}
	if got := seen("device:printer"); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("a plain device finds %v", got)
	}
	if !d.CheckPassword("carol", "purple-ladder-3") || !d.CheckPassword("alice", "orange-kettle-7") || d.CheckPassword("dave", "silver-window-9") {
		t.Fatalf("binds: carol (mail) and alice (ldap) yes, dave no")
	}
	if got := seen("carol"); !slices.Equal(got, []string{"carol"}) {
		t.Fatalf("carol, bound, finds %v", got)
	}
	if got := seen("alice"); !slices.Equal(got, []string{"alice"}) {
		t.Fatalf("alice, bound, finds %v", got)
	}
	// the device back to LDAP itself
	if x := r.ok("PATCH", "/v1/ldap/devices/mailsrv", map[string]any{"service": "ldap"}); x["service"] != "" {
		t.Fatalf("back to LDAP: %v", x)
	}
	if d.CheckPassword("carol", "purple-ladder-3") {
		t.Fatalf("carol binds after the device left mail")
	}
}

func TestOlderStateStaysOpen(t *testing.T) {
	r, _ := newNativeRig(t)
	r.s.openUnbound = false
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "password": "orange-kettle-7", "groups": []string{AdminGroup}})
	gw := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "gateway", "group": "telework"})
	plain := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "fileserver"})
	mail := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})
	r.call("PUT", "/v1/sync/offers", "Bearer "+mail["key"].(string), map[string]any{"mail_domains": []string{"acme.example"}})
	// as a keelAuth from before 2026-11-15 left it
	r.s.update(func(st *State) error { st.ClosedDefault = false; return nil }, false)
	if err := r.s.BringUp(); err != nil {
		t.Fatal(err)
	}
	st := r.s.State()
	if !st.ClosedDefault || st.ServiceGroups[AccessSMB] != "*" || st.ServiceGroups["sync:"+plain["id"].(string)] != "*" ||
		st.ServiceGroups["sync:"+gw["id"].(string)] != "telework" || st.ServiceGroups["sync:"+mail["id"].(string)] != "" {
		t.Fatalf("after the upgrade: %v", st.ServiceGroups)
	}
	for _, c := range r.ok("GET", "/v1/consumers", nil)["consumers"].([]any) {
		m := c.(map[string]any)
		want := map[string]string{"sync:" + gw["id"].(string): "group", "sync:" + mail["id"].(string): "ticks"}[m["id"].(string)]
		if want == "" {
			want = "all"
		}
		if m["scope"] != want {
			t.Fatalf("%v after the upgrade: %v, want %s", m["id"], m["scope"], want)
		}
	}
	// what is made from now on starts closed; the upgrade does not run twice
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "later"})
	if err := r.s.closeByDefault(); err != nil {
		t.Fatal(err)
	}
	if c := consumerOf(t, r, "sync:"+k["id"].(string)); c["scope"] != "none" {
		t.Fatalf("a key made after the upgrade: %v", c)
	}
}
