package adimport

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	"keelauth/internal/module/ldap"
)

// fakeDir answers Read's three searches in order: the root, the groups, the people.
type fakeDir struct {
	calls  int
	groups []ldap.Entry
	people []ldap.Entry
}

func entry(dn string, kv ...string) ldap.Entry {
	e := ldap.Entry{DN: dn, Attrs: map[string][]string{}}
	for i := 0; i < len(kv); i += 2 {
		k := strings.ToLower(kv[i])
		e.Attrs[k] = append(e.Attrs[k], kv[i+1])
	}
	return e
}

func (f *fakeDir) Search(base string, baseOnly bool, _ ldap.Filter, _ []string, each func(ldap.Entry) error) error {
	f.calls++
	var es []ldap.Entry
	switch f.calls {
	case 1:
		es = []ldap.Entry{entry("", "defaultNamingContext", "DC=ad,DC=Example,DC=com")}
	case 2:
		es = f.groups
	case 3:
		es = f.people
	}
	for _, e := range es {
		if err := each(e); err != nil {
			return err
		}
	}
	return nil
}

const base = ",DC=ad,DC=Example,DC=com"

func testDir(t *testing.T) *Directory {
	f := &fakeDir{
		groups: []ldap.Entry{
			entry("CN=Sales Tokyo,OU=G"+base, "sAMAccountName", "Sales Tokyo", "description", "sales", "memberOf", "CN=Staff,OU=G"+base),
			entry("CN=Staff,OU=G"+base, "sAMAccountName", "Staff", "memberOf", "CN=Sales Tokyo,OU=G"+base), // a loop
			entry("CN=営業,OU=G"+base, "sAMAccountName", "営業"),
			entry("CN=Domain Users,CN=Users"+base, "sAMAccountName", "Domain Users", "isCriticalSystemObject", "TRUE"),
			entry("CN=Users,CN=Builtin"+base, "sAMAccountName", "Users"),
		},
		people: []ldap.Entry{
			entry("CN=田中 太郎,OU=P"+base, "sAMAccountName", "Tanaka", "userPrincipalName", "t.tanaka@ad.example.com",
				"displayName", "田中 太郎", "mail", "Taro.Tanaka@Old.co.jp", "proxyAddresses", "SMTP:Taro.Tanaka@Old.co.jp",
				"proxyAddresses", "smtp:tt@old.co.jp", "sn", "田中", "givenName", "太郎", "msDS-PhoneticLastName", "タナカ",
				"employeeID", "00123", "userAccountControl", "512", "memberOf", "cn=sales tokyo,OU=G"+base, "memberOf", "CN=営業,OU=G"+base,
				"memberOf", "CN=Domain Users,CN=Users"+base),
			entry("CN=Sato,OU=P"+base, "sAMAccountName", "sato", "mail", "sato@partner.example", "userAccountControl", "66048"),
			entry("CN=Gone,OU=P"+base, "sAMAccountName", "gone", "userAccountControl", "514", "memberOf", "CN=Staff,OU=G"+base),
			entry("CN=Suzuki,OU=P"+base, "sAMAccountName", "1suzuki", "mail", "suzuki@old.co.jp", "userAccountControl", "512"),
			entry("CN=Old Hand,OU=P"+base, "sAMAccountName", "oldhand", "mail", "taro.tanaka@old.co.jp", "userAccountControl", "512", "memberOf", "CN=Staff,OU=G"+base),
			entry("CN=Administrator,CN=Users"+base, "sAMAccountName", "Administrator", "isCriticalSystemObject", "TRUE"),
			entry("CN=PC01,CN=Computers"+base, "sAMAccountName", "PC01$"),
		},
	}
	d, err := Read(f)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var (
	userRE  = regexp.MustCompile(`^[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)*$`)
	groupRE = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

func testEnv() Env {
	return Env{
		HaveUser:    func(n string) bool { return n == "oldhand" },
		HaveGroup:   func(n string) bool { return n == "staff" },
		ValidUser:   func(n string) bool { return len(n) <= 32 && userRE.MatchString(n) },
		ValidGroup:  groupRE.MatchString,
		MailDomains: []string{"new.co.jp"},
	}
}

func texts(ns []Note) string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Text)
	}
	return strings.Join(out, "|")
}

func row(p *Plan, sam string) Row {
	for _, r := range p.Rows {
		if r.Sam == sam {
			return r
		}
	}
	return Row{}
}

func TestRead(t *testing.T) {
	d := testDir(t)
	if d.Domain != "ad.example.com" || len(d.People) != 5 || len(d.Groups) != 3 {
		t.Fatalf("domain %q, %d people, %d groups", d.Domain, len(d.People), len(d.Groups))
	}
	var tanaka Person
	for _, p := range d.People {
		if p.Sam == "Tanaka" {
			tanaka = p
		}
	}
	want := Person{Sam: "Tanaka", UPN: "t.tanaka@ad.example.com", DisplayName: "田中 太郎", Mail: "Taro.Tanaka@Old.co.jp",
		Aliases: []string{"tt@old.co.jp"}, Sn: "田中", GivenName: "太郎", PhoneticLast: "タナカ", EmployeeNumber: "00123",
		Groups: []string{"Sales Tokyo", "Staff", "営業"}}
	if !reflect.DeepEqual(tanaka, want) {
		t.Fatalf("tanaka: %+v", tanaka)
	}
	if got := d.MailDomains(); !reflect.DeepEqual(got, []string{"old.co.jp", "partner.example"}) {
		t.Fatalf("mail domains %v", got)
	}
}

func TestMapDefaults(t *testing.T) {
	p := Map(testDir(t), Mapping{}, testEnv())
	tanaka, sato, gone, suzuki, old := row(p, "Tanaka"), row(p, "sato"), row(p, "gone"), row(p, "1suzuki"), row(p, "oldhand")
	if tanaka.Name != "tanaka" || !tanaka.Ticked || tanaka.Problem != "" || tanaka.Contact != "Taro.Tanaka@Old.co.jp" || len(tanaka.MailDomains) != 0 {
		t.Fatalf("tanaka: %+v", tanaka)
	}
	if !reflect.DeepEqual(tanaka.NewGroups, []string{"sales-tokyo", "staff"}) { // 営業 has no usable name
		t.Fatalf("tanaka's groups: %v", tanaka.NewGroups)
	}
	if !sato.Ticked || sato.Contact != "sato@partner.example" {
		t.Fatalf("sato: %+v", sato)
	}
	if gone.Ticked || !gone.Disabled {
		t.Fatalf("a disabled account is not ticked by default: %+v", gone)
	}
	if !suzuki.Ticked || suzuki.Problem == "" {
		t.Fatalf("a name keelAuth cannot take is in the way: %+v", suzuki)
	}
	if old.Ticked || !old.Exists || old.Problem != "" {
		t.Fatalf("an account keelAuth has is left alone: %+v", old)
	}
	g := map[string]GroupRow{}
	for _, gr := range p.Groups {
		g[gr.AD] = gr
	}
	if s := g["Staff"]; !s.Ticked || !s.Exists || !reflect.DeepEqual(s.Members, []string{"oldhand", "tanaka"}) {
		t.Fatalf("staff: %+v", s) // the person keelAuth already has is put into the group too
	}
	if e := g["営業"]; !e.Ticked || e.Problem == "" {
		t.Fatalf("営業 needs a name typed: %+v", e)
	}
	if p.Problems != 2 { // 1suzuki and 営業
		t.Fatalf("%d problems", p.Problems)
	}
	if !reflect.DeepEqual(p.Mail, map[string]MailRule{"old.co.jp": {To: "keep"}, "partner.example": {To: "keep"}}) {
		t.Fatalf("mail rules: %v", p.Mail)
	}
}

func TestMapChoices(t *testing.T) {
	m := Mapping{
		NameFrom: "mail",
		Rename:   map[string]string{"1suzuki": "suzuki"},
		Mail:     map[string]MailRule{"old.co.jp": {To: "domain", Domain: "New.co.jp"}, "partner.example": {To: "drop"}},
		Users:    []string{"Tanaka", "sato", "1suzuki", "gone"},
		Groups:   map[string]string{"営業": "eigyo", "Sales Tokyo": ""},
	}
	p := Map(testDir(t), m, testEnv())
	tanaka := row(p, "Tanaka")
	if tanaka.Name != "taro.tanaka" || !reflect.DeepEqual(tanaka.Addresses, []string{"taro.tanaka@new.co.jp"}) ||
		!reflect.DeepEqual(tanaka.MailDomains, []string{"new.co.jp"}) || tanaka.Contact != "" ||
		!reflect.DeepEqual(tanaka.NewGroups, []string{"eigyo", "sales-tokyo"}) {
		t.Fatalf("tanaka: %+v", tanaka)
	}
	// the name comes from the address, so only the domain changes: not said; the alias is
	if n := texts(tanaka.Notes); strings.Contains(n, "address changes") || !strings.Contains(n, "tt@old.co.jp") {
		t.Fatalf("tanaka's notes: %v", tanaka.Notes)
	}
	bySam := Map(testDir(t), Mapping{Mail: m.Mail}, testEnv())
	if n := texts(row(bySam, "Tanaka").Notes); !strings.Contains(n, "address changes: Taro.Tanaka@Old.co.jp -> tanaka@new.co.jp") {
		t.Fatalf("tanaka by AD name: %v", n)
	}
	if s := row(p, "1suzuki"); s.Name != "suzuki" || s.Problem != "" || len(s.Notes) != 0 { // suzuki@old -> suzuki@new: only the domain changed, not said
		t.Fatalf("suzuki: %+v", s)
	}
	if s := row(p, "sato"); s.Contact != "" || len(s.Addresses) != 0 || s.Problem != "" {
		t.Fatalf("sato (mail dropped): %+v", s)
	}
	if g := row(p, "gone"); !g.Ticked || g.Name != "gone" || len(g.Notes) != 2 {
		t.Fatalf("gone (no mail, disabled, ticked): %+v", g)
	}
	if p.Problems != 0 {
		t.Fatalf("%d problems: %+v", p.Problems, p)
	}

	// Two ticked people wanting one name.
	m.Rename["sato"] = "suzuki"
	p = Map(testDir(t), m, testEnv())
	if a, b := row(p, "sato"), row(p, "1suzuki"); !strings.Contains(a.Problem, "2 ticked people") || !strings.Contains(b.Problem, "2 ticked people") || p.Problems != 2 {
		t.Fatalf("same name twice: %q / %q, %d problems", a.Problem, b.Problem, p.Problems)
	}
	// A ticked account keelAuth already has.
	p = Map(testDir(t), Mapping{Users: []string{"oldhand"}}, testEnv())
	if o := row(p, "oldhand"); !strings.Contains(o.Problem, "already") || p.Problems != 1 {
		t.Fatalf("oldhand ticked: %+v", o)
	}
	// A domain the mail server does not have.
	p = Map(testDir(t), Mapping{Mail: map[string]MailRule{"old.co.jp": {To: "domain", Domain: "nowhere.example"}}}, testEnv())
	if tk := row(p, "Tanaka"); !strings.Contains(tk.Problem, "nowhere.example") {
		t.Fatalf("tanaka: %+v", tk)
	}
}

func TestGroupName(t *testing.T) {
	for in, want := range map[string]string{"Sales Tokyo": "sales-tokyo", "R&D (JP)": "r-d-jp", "営業": "", "dev_ops": "dev_ops",
		"A very long group name that goes on and on": "a-very-long-group-name-that-goes"} {
		if got := GroupName(in); got != want {
			t.Errorf("GroupName(%q) = %q, want %q", in, got, want)
		}
	}
}
