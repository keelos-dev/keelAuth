package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keelauth/internal/adimport"
	"keelauth/internal/module/ldap"
)

func TestADImport(t *testing.T) {
	r := newRig(t)
	now := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
	r.s.Now = func() time.Time { return now }
	dir := &adimport.Directory{Domain: "ad.example.com",
		People: []adimport.Person{
			{Sam: "Tanaka", DisplayName: "田中 太郎", Mail: "taro.tanaka@old.co.jp", Groups: []string{"Sales Tokyo", "営業"}},
			{Sam: "1suzuki", DisplayName: "Suzuki", Mail: "suzuki@old.co.jp", Groups: []string{"Sales Tokyo"}},
			{Sam: "sato", Mail: "sato@partner.example"},
			{Sam: "gone", Disabled: true},
			{Sam: "alice", DisplayName: "AD's Alice", Groups: []string{"Sales Tokyo"}},
		},
		Groups: []adimport.Group{{Name: "Sales Tokyo", Description: "sales"}, {Name: "営業"}}}
	r.s.ADRead = func(_ context.Context, address, user, password, pin string) (*adimport.Directory, string, error) {
		switch {
		case pin != "f1f1":
			return nil, "", &ldap.PinError{Got: "f1f1"}
		case password != "pw":
			return nil, "f1f1", ldap.ErrUpstreamLogin
		}
		return dir, "f1f1", nil
	}
	// keelAuth has alice already, and a mail server with a domain that is ticked per account.
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "password": "correct horse battery staple"})
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})
	r.call("PUT", "/v1/sync/offers", "Bearer "+k["key"].(string), map[string]any{"mail_domains": []string{"new.co.jp"}})

	conn := map[string]any{"address": "dc1.ad.example.com", "user": `AD\reader`, "password": "pw"}
	o := r.ok("POST", "/v1/import/ad/read", conn)
	if o["confirm_certificate"] != "f1f1" || o["id"] != nil {
		t.Fatalf("first the certificate is shown: %v", o)
	}
	conn["fingerprint"] = "f1f1"
	conn["password"] = "wrong"
	if code, o, _ := r.call("POST", "/v1/import/ad/read", "", conn); code != 400 || o["code"] != "ad_login" {
		t.Fatalf("wrong AD password: %d %v", code, o)
	}
	conn["password"] = "pw"
	o = r.ok("POST", "/v1/import/ad/read", conn)
	id := o["id"].(string)
	plan := o["plan"].(map[string]any)
	if o["domain"] != "ad.example.com" || plan["problems"].(float64) != 2 { // 1suzuki, 営業
		t.Fatalf("read: %v", o)
	}
	rows := func(p map[string]any) map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, x := range p["users"].([]any) {
			out[x.(map[string]any)["sam"].(string)] = x.(map[string]any)
		}
		return out
	}
	if a := rows(plan)["alice"]; a["exists"] != true || a["ticked"] != false {
		t.Fatalf("alice is in keelAuth already: %v", a)
	}

	// The first run takes the sound rows and leaves the red ones.
	choices := map[string]any{"id": id, "mail": map[string]any{"old.co.jp": map[string]any{"to": "domain", "domain": "new.co.jp"}}}
	o = r.ok("POST", "/v1/import/ad/run", choices)
	made := o["made"].([]any)
	if len(made) != 2 || len(o["failed"].([]any)) != 0 {
		t.Fatalf("first run: %v", o)
	}
	if n := o["notes"].(map[string]any); len(n) != 0 { // only accounts with something to say are in it
		t.Fatalf("notes: %v", n)
	}
	tanaka := made[0].(map[string]any)
	if tanaka["name"] != "tanaka" || tanaka["addresses"].([]any)[0] != "tanaka@new.co.jp" || len(tanaka["password"].(string)) < 8 {
		t.Fatalf("tanaka: %v", tanaka)
	}
	left := rows(o["plan"].(map[string]any))
	if left["Tanaka"]["exists"] != true || left["1suzuki"]["problem"] == "" || left["1suzuki"]["ticked"] != true {
		t.Fatalf("after the first run: %v", left)
	}
	u := r.ok("GET", "/v1/users/tanaka", nil)
	if u["display_name"] != "田中 太郎" || u["must_change"] != true || u["groups"].([]any)[0] != "sales-tokyo" {
		t.Fatalf("tanaka in keelAuth: %v", u)
	}
	if s := r.ok("GET", "/v1/users/sato", nil); s["mail"] != "sato@partner.example" {
		t.Fatalf("sato keeps the address as contact: %v", s)
	}
	g := r.ok("GET", "/v1/groups", nil)["groups"].([]any)
	var sales map[string]any
	for _, x := range g {
		if x.(map[string]any)["name"] == "sales-tokyo" {
			sales = x.(map[string]any)
		}
	}
	if sales == nil || len(sales["members"].([]any)) != 2 { // tanaka and alice, who was there before
		t.Fatalf("sales-tokyo: %v", sales)
	}
	if a := r.ok("GET", "/v1/users/alice", nil); a["display_name"] != "Alice" {
		t.Fatalf("alice was changed: %v", a)
	}

	// The administrator gives the red rows names, ticks the disabled account, and goes on.
	choices["rename"] = map[string]any{"1suzuki": "suzuki"}
	choices["groups"] = map[string]any{"営業": "eigyo", "Sales Tokyo": ""}
	choices["users"] = []string{"1suzuki", "gone"}
	if p := r.ok("POST", "/v1/import/ad/preview", choices)["plan"].(map[string]any); p["problems"].(float64) != 0 {
		t.Fatalf("preview after the corrections: %v", p)
	}
	o = r.ok("POST", "/v1/import/ad/run", choices)
	if len(o["made"].([]any)) != 2 || len(o["failed"].([]any)) != 0 || o["groups"].([]any)[0] != "eigyo" {
		t.Fatalf("second run: %v", o)
	}
	if gone := r.ok("GET", "/v1/users/gone", nil); gone["enabled"] != false {
		t.Fatalf("gone is imported disabled: %v", gone)
	}
	if u := r.ok("GET", "/v1/users/tanaka", nil); len(u["groups"].([]any)) != 2 {
		t.Fatalf("tanaka joins the group named later: %v", u)
	}

	// The table has all four, as often as asked, until the read is forgotten.
	csvOf := func() (int, string) {
		req := httptest.NewRequest("GET", "/v1/import/ad/"+id+"/passwords.csv", nil)
		req.Header.Set("Authorization", "Bearer "+r.key)
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	code, body := csvOf()
	lines := strings.Split(strings.TrimSpace(body), "\r\n")
	if code != 200 || len(lines) != 5 || !strings.Contains(body, "tanaka,田中 太郎,tanaka@new.co.jp,"+tanaka["password"].(string)) || !strings.Contains(body, "suzuki,Suzuki,suzuki@new.co.jp,") {
		t.Fatalf("password table: %d\n%s", code, body)
	}
	if code, again := csvOf(); code != 200 || again != body {
		t.Fatal("the table can be fetched again")
	}
	now = now.Add(16 * time.Minute)
	if code, _ := csvOf(); code != http.StatusNotFound {
		t.Fatalf("after 15 minutes: %d", code)
	}
	if code, o, _ := r.call("POST", "/v1/import/ad/run", "", choices); code != 404 || o["code"] != "ad_read_gone" {
		t.Fatalf("run after 15 minutes: %d %v", code, o)
	}
}
