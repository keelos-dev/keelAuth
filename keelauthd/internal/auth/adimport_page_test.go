package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"keelauth/internal/adimport"
	"keelauth/internal/module/ldap"
)

// TestADImportPage is not a test but a stand for looking at the import dialog in a browser:
//
//	KEELAUTH_ADIMPORT_PAGE=127.0.0.1:2299 go test -run TestADImportPage -timeout 30m ./internal/auth
//
// serves keelAuth's page there for 20 minutes with a made-up AD behind "Import from AD"
// (any address; AD account reader, password pw) and the administrator admin1 / the password below.
// With KEELAUTH_ADIMPORT_REAL=1 there is no made-up AD: the dialog reads the directory typed into it.
func TestADImportPage(t *testing.T) {
	addr := os.Getenv("KEELAUTH_ADIMPORT_PAGE")
	if addr == "" {
		t.Skip("set KEELAUTH_ADIMPORT_PAGE=host:port to serve the page")
	}
	r := newRig(t)
	people := []adimport.Person{
		{Sam: "Tanaka", UPN: "t.tanaka@ad.example.com", DisplayName: "田中 太郎", Mail: "taro.tanaka@old.co.jp", Aliases: []string{"tt@old.co.jp"}, Groups: []string{"Sales Tokyo", "営業"}},
		{Sam: "1suzuki", DisplayName: "鈴木 花子", Mail: "suzuki@old.co.jp", Groups: []string{"Sales Tokyo"}},
		{Sam: "sato", DisplayName: "Sato Ken", Mail: "sato@partner.example"},
		{Sam: "gone", DisplayName: "Left Last Year", Disabled: true},
		{Sam: "alice", DisplayName: "AD's Alice", Groups: []string{"Sales Tokyo"}},
		{Sam: "Very.Long.Name.That.Does.Not.Fit.Anywhere", DisplayName: "Long Name"},
	}
	for i := 0; i < 40; i++ {
		people = append(people, adimport.Person{Sam: fmt.Sprintf("staff%02d", i), DisplayName: fmt.Sprintf("社員 %02d", i),
			Mail: fmt.Sprintf("staff%02d@old.co.jp", i), Groups: []string{"Staff"}})
	}
	dir := &adimport.Directory{Domain: "ad.example.com", People: people,
		Groups: []adimport.Group{{Name: "Sales Tokyo", Description: "sales"}, {Name: "Staff"}, {Name: "営業"}, {Name: "Empty"}}}
	r.s.ADRead = func(_ context.Context, address, user, password, pin string) (*adimport.Directory, string, error) {
		switch {
		case pin != "f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788":
			return nil, "", &ldap.PinError{Got: "f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788f1e2d3c4b5a69788"}
		case password != "pw":
			return nil, "", ldap.ErrUpstreamLogin
		}
		return dir, pin, nil
	}
	if os.Getenv("KEELAUTH_ADIMPORT_REAL") != "" {
		r.s.ADRead = nil // the dialog reads whatever directory is typed into it
	}
	r.ok("POST", "/v1/users", map[string]any{"name": "admin1", "display_name": "Admin", "password": "correct horse battery staple", "groups": []string{AdminGroup}})
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "password": "correct horse battery staple"})
	k := r.ok("POST", "/v1/sync/keys", map[string]any{"name": "mail1"})
	r.call("PUT", "/v1/sync/offers", "Bearer "+k["key"].(string), map[string]any{"mail_domains": []string{"new.co.jp"}})
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go http.Serve(ln, r.h)
	t.Logf("serving on http://%s for 20 minutes", addr)
	time.Sleep(20 * time.Minute)
}
