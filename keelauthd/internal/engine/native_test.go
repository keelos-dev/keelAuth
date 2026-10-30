package engine

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeUsersGroupsPersist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "accounts.json")
	n, err := NewNative(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Prepare("keelauth-admins"); err != nil {
		t.Fatal(err)
	}
	u, err := n.CreateUser("alice", "Alice", "alice@example.com")
	if err != nil || u.UID < firstID || !u.Enabled || u.UUID == "" {
		t.Fatalf("create: %+v %v", u, err)
	}
	if _, err := n.CreateUser("alice", "", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := n.CreateGroup("alice", ""); !errors.Is(err, ErrExists) {
		t.Fatalf("group with a user's name: %v", err)
	}
	if _, err := n.CreateGroup("staff", "everybody"); err != nil {
		t.Fatal(err)
	}
	if err := n.SetMembers("staff", []string{"alice"}); err != nil {
		t.Fatal(err)
	}
	if err := n.SetMembers("keelauth-admins", []string{"staff"}); err != nil {
		t.Fatal(err)
	}
	if err := n.SetMembers("staff", []string{"nobody"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown member: %v", err)
	}
	if err := n.SetPassword("alice", "Correct-Horse-Battery-9"); err != nil {
		t.Fatal(err)
	}
	// a second open sees everything
	n2, err := NewNative(p)
	if err != nil {
		t.Fatal(err)
	}
	u2, err := n2.User("alice")
	if err != nil || u2.DisplayName != "Alice" || strings.Join(u2.Groups, ",") != "staff" || u2.UID != u.UID {
		t.Fatalf("reopened: %+v %v", u2, err)
	}
	g, _ := n2.Group("keelauth-admins")
	if strings.Join(g.MemberGroups, ",") != "staff" || len(g.Members) != 0 {
		t.Fatalf("nested group: %+v", g)
	}
	if ok, _ := n2.CheckPassword("alice", "Correct-Horse-Battery-9"); !ok {
		t.Fatal("password does not verify after reopen")
	}
	if ok, _ := n2.CheckPassword("alice", "wrong"); ok {
		t.Fatal("wrong password accepted")
	}
	if !strings.HasPrefix(n2.PasswordHash("alice"), "$pbkdf2-sha256$i=600000$") {
		t.Fatalf("hash: %s", n2.PasswordHash("alice"))
	}
	if err := n2.SetEnabled("alice", false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := n2.CheckPassword("alice", "Correct-Horse-Battery-9"); ok {
		t.Fatal("disabled user logs in")
	}
	if err := n2.DeleteUser("alice"); err != nil {
		t.Fatal(err)
	}
	g, _ = n2.Group("staff")
	if len(g.Members) != 0 {
		t.Fatalf("deleted user still a member: %+v", g)
	}
	if err := n2.DeleteGroup("staff"); err != nil {
		t.Fatal(err)
	}
	g, _ = n2.Group("keelauth-admins")
	if len(g.MemberGroups) != 0 {
		t.Fatalf("deleted group still nested: %+v", g)
	}
}

func TestNativeClientsAndDevices(t *testing.T) {
	n, _ := NewNative("")
	n.Seal = func(v string) string { return "sealed:" + v }
	n.Open = func(v string) (string, error) { return strings.TrimPrefix(v, "sealed:"), nil }
	if err := n.CreateOAuth2(OAuth2{Name: "app", DisplayName: "App", RedirectURLs: []string{"https://app/cb"}, PKCE: true}); err != nil {
		t.Fatal(err)
	}
	sec, err := n.OAuth2Secret("app", false)
	if err != nil || len(sec) < 40 || strings.HasPrefix(sec, "sealed:") {
		t.Fatalf("secret: %q %v", sec, err)
	}
	if n.d.Secrets["app"] != "sealed:"+sec {
		t.Fatalf("secret not sealed in the store: %q", n.d.Secrets["app"])
	}
	sec2, _ := n.OAuth2Secret("app", true)
	if sec2 == sec {
		t.Fatal("reset gave the same secret")
	}
	if _, err := n.CreateGroup("staff", ""); err != nil {
		t.Fatal(err)
	}
	if err := n.SetScopeMap("app", "staff", []string{"openid", "email"}); err != nil {
		t.Fatal(err)
	}
	if err := n.SetScopeMap("app", "ghost", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scope map for an unknown group: %v", err)
	}
	if err := n.DeleteGroup("staff"); err != nil {
		t.Fatal(err)
	}
	c, _ := n.OAuth2("app")
	if len(c.ScopeMaps) != 0 {
		t.Fatalf("scope map survived the group: %+v", c.ScopeMaps)
	}
	if err := n.CreateServiceAccount("printer2", "NAS", []string{"readers"}); err != nil {
		t.Fatal(err)
	}
	tok, err := n.NewAPIToken("printer2", "x")
	if err != nil || !strings.HasPrefix(tok, "kad_") {
		t.Fatalf("token: %q %v", tok, err)
	}
	if !n.CheckToken("printer2", tok) || n.CheckToken("printer2", tok+"x") || n.CheckToken("nobody", tok) {
		t.Fatal("token check")
	}
	tok2, _ := n.NewAPIToken("printer2", "x")
	if n.CheckToken("printer2", tok) || !n.CheckToken("printer2", tok2) {
		t.Fatal("old token still works after a new one")
	}
	sas, _ := n.ServiceAccounts()
	if len(sas) != 1 || sas[0].Tokens != 1 {
		t.Fatalf("service accounts: %+v", sas)
	}
	if err := n.DeleteServiceAccount("printer2"); err != nil {
		t.Fatal(err)
	}
}

func TestNativePasswordPolicy(t *testing.T) {
	cases := []struct {
		p    Policy
		name string
		pw   string
		want string // substring of the refusal, "" = accepted
	}{
		{Policy{}, "alice", "short", "at least 8"},
		{Policy{}, "alice", "alice123", ""}, // the default looks at the length only
		{Policy{}, "alice", "Correct-Horse-Battery-9", ""},
		{Policy{10, "length"}, "alice", "alicealice", ""}, // length only: the name is fine
		{Policy{10, "normal"}, "alice", "alice12345", "user name"},
		{Policy{10, "normal"}, "alice", "password123", "common"},
		{Policy{10, "normal"}, "alice", "aaaaaaaaaa", "common"},
		{Policy{10, "normal"}, "alice", "qwertyuiop1", "common"},
		{Policy{10, "normal"}, "alice", "horsebatterystaple", ""},
		{Policy{10, "strict"}, "alice", "horsebatterystaple", "three kinds"},
		{Policy{10, "strict"}, "alice", "horse-battery-staple-ok", ""}, // 20+: kinds not required
		{Policy{10, "strict"}, "alice", "Horse-battery9", ""},
	}
	for _, c := range cases {
		got := CheckQuality(c.p, c.name, c.pw)
		if (c.want == "" && got != "") || (c.want != "" && !strings.Contains(got, c.want)) {
			t.Errorf("%+v %q: got %q, want %q", c.p, c.pw, got, c.want)
		}
	}
	n, _ := NewNative("")
	n.SetPolicy(Policy{10, "normal"})
	n.CreateUser("bob", "", "")
	var we *WeakPasswordError
	if err := n.SetPassword("bob", "bob-bob-bob"); !errors.As(err, &we) {
		t.Fatalf("weak password not refused as WeakPasswordError: %v", err)
	}
	if err := n.SetPassword("bob", "orange-kettle-7"); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyPasswordFormats(t *testing.T) {
	h := HashPassword("x")
	if !VerifyPassword(h, "x") || VerifyPassword(h, "y") || VerifyPassword("", "x") || VerifyPassword("$argon2id$x", "x") {
		t.Fatal("verify")
	}
}
