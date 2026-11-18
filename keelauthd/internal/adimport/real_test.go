package adimport

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"keelauth/internal/module/ldap"
)

// TestRealAD reads a real directory (a Samba AD DC or a Windows one) and prints what Read made
// of it:
//
//	KEELAUTH_AD=127.0.0.1:2636 KEELAUTH_AD_USER='reader@ad.example.com' KEELAUTH_AD_PASSWORD=... \
//	  go test -count=1 -v -run TestRealAD ./internal/adimport
//
// With KEELAUTH_AD_TESTDATA=1 the directory is the test one of docs/07 §6 (the Samba VM's
// mkdata.sh) and what was read is checked against it.
func TestRealAD(t *testing.T) {
	addr := os.Getenv("KEELAUTH_AD")
	if addr == "" {
		t.Skip("set KEELAUTH_AD, KEELAUTH_AD_USER, KEELAUTH_AD_PASSWORD to read a real directory")
	}
	user, pw := os.Getenv("KEELAUTH_AD_USER"), os.Getenv("KEELAUTH_AD_PASSWORD")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, err := ldap.DialUpstream(ctx, addr, "")
	var pin *ldap.PinError
	if !errors.As(err, &pin) {
		t.Fatalf("the first connection should show the certificate: %v", err)
	}
	t.Logf("certificate fingerprint %s", pin.Got)
	u, err := ldap.DialUpstream(ctx, addr, pin.Got)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	t.Logf("connected, StartTLS=%v", u.StartTLS)
	if err := u.Bind(user, pw+"-wrong"); !errors.Is(err, ldap.ErrUpstreamLogin) {
		t.Fatalf("a wrong password: %v", err)
	}
	if err := u.Bind(user, pw); err != nil {
		t.Fatalf("bind as %s: %v", user, err)
	}
	start := time.Now()
	d, err := Read(u)
	if err != nil {
		t.Fatal(err)
	}
	disabled := 0
	for _, p := range d.People {
		if p.Disabled {
			disabled++
		}
	}
	t.Logf("%s: %d people (%d disabled), %d groups, mail domains %v, read in %v", d.Domain, len(d.People), disabled, len(d.Groups), d.MailDomains(), time.Since(start).Round(time.Millisecond))
	for i, g := range d.Groups {
		if i < 20 {
			t.Logf("group %q %q", g.Name, g.Description)
		}
	}
	by := map[string]Person{}
	for i, p := range d.People {
		by[p.Sam] = p
		if i < 8 {
			t.Logf("person %+v", p)
		}
	}
	if os.Getenv("KEELAUTH_AD_TESTDATA") == "" {
		return
	}
	names := map[string]bool{}
	for _, g := range d.Groups {
		names[g.Name] = true
	}
	if names["Domain Users"] || names["Domain Admins"] || names["Administrators"] {
		t.Errorf("system groups are listed: %v", names)
	}
	if d.Domain != "ad.example.com" || len(d.People) != 1605 || disabled != 1 {
		t.Errorf("want ad.example.com with 1605 people (reader, 4 by hand, 1600 in bulk; not Administrator, Guest, krbtgt), 1 disabled")
	}
	tk := by["Tanaka"]
	if tk.DisplayName != "田中 太郎" || tk.Mail != "Taro.Tanaka@old.co.jp" || tk.Sn != "田中" || tk.GivenName != "太郎" || tk.PhoneticLast != "タナカ" ||
		tk.PhoneticFirst != "タロウ" || tk.EmployeeNumber != "00123" || len(tk.Aliases) != 1 || tk.Aliases[0] != "tt@old.co.jp" || tk.UPN != "Tanaka@ad.example.com" {
		t.Errorf("Tanaka: %+v", tk)
	}
	if g := tk.Groups; len(g) != 3 || g[0] != "Sales Tokyo" || g[1] != "Staff" || g[2] != "営業" { // Staff through Sales Tokyo
		t.Errorf("Tanaka's groups: %v", g)
	}
	if g := by["gone"]; !g.Disabled || len(g.Groups) != 1 || g.Groups[0] != "Staff" {
		t.Errorf("gone: %+v", g)
	}
	if p := by["staff1599"]; p.DisplayName != "社員 1599" || p.Mail != "staff1599@old.co.jp" || len(p.Groups) != 1 || p.Groups[0] != "All Hands" || p.Disabled {
		t.Errorf("staff1599: %+v", p)
	}
	for _, sys := range []string{"Administrator", "Guest", "krbtgt"} {
		if _, ok := by[sys]; ok {
			t.Errorf("%s is a system account and should not be listed", sys)
		}
	}
	// groups the directory made itself that are not marked as system objects (DnsAdmins,
	// DnsUpdateProxy) are listed too: nobody ticked is in them, so they stay unticked
	if !names["Sales Tokyo"] || !names["Staff"] || !names["営業"] || !names["All Hands"] {
		t.Errorf("groups: %v", names)
	}
}
