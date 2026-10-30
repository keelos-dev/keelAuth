package ldap

import (
	"crypto/tls"
	"errors"
	"os"

	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// ---- a small client for the tests (same BER) ----

type client struct {
	c  net.Conn
	id int
}

func (cl *client) send(op []byte) {
	cl.id++
	cl.c.Write(encSeq(encInt(tagInteger, cl.id), op))
}

func (cl *client) read() (elem, error) {
	msg, err := readMessage(cl.c)
	if err != nil {
		return elem{}, err
	}
	parts, err := msg.children()
	if err != nil || len(parts) < 2 {
		return elem{}, errors.New("bad message")
	}
	return parts[1], nil
}

func (cl *client) bind(dn, pw string) (int, string) {
	cl.send(encApp(appBindRequest, encInt(tagInteger, 3), encStr(dn), enc(classContext|0, []byte(pw))))
	op, err := cl.read()
	if err != nil {
		return -1, err.Error()
	}
	parts, _ := op.children()
	code, _ := parts[0].int()
	return code, parts[2].str()
}

type found struct {
	dn    string
	attrs map[string][]string
}

func (cl *client) search(base string, scope int, filter string, attrs ...string) (int, []found) {
	var as []byte
	for _, a := range attrs {
		as = append(as, encStr(a)...)
	}
	cl.send(encApp(appSearchRequest, encStr(base), encEnum(scope), encEnum(0), encInt(tagInteger, 0), encInt(tagInteger, 0), encBool(false), textFilter(filter), encSeq(as)))
	var out []found
	for {
		op, err := cl.read()
		if err != nil {
			return -1, nil
		}
		switch op.tag &^ constructed &^ classApplication {
		case appSearchEntry:
			parts, _ := op.children()
			r := found{dn: parts[0].str(), attrs: map[string][]string{}}
			list, _ := parts[1].children()
			for _, a := range list {
				kv, _ := a.children()
				vals, _ := kv[1].children()
				for _, v := range vals {
					r.attrs[kv[0].str()] = append(r.attrs[kv[0].str()], v.str())
				}
			}
			out = append(out, r)
		case appSearchDone:
			parts, _ := op.children()
			code, _ := parts[0].int()
			return code, out
		default:
			return -1, nil
		}
	}
}

func (cl *client) whoami() string {
	cl.send(encApp(appExtendedRequest, enc(classContext|0, []byte(whoamiOID))))
	op, _ := cl.read()
	parts, _ := op.children()
	for _, p := range parts {
		if p.tag == classContext|11 {
			return p.str()
		}
	}
	return ""
}

// textFilter encodes an RFC 4515 filter (the subset the tests use).
func textFilter(f string) []byte {
	b, rest := encText(strings.TrimSpace(f))
	if rest != "" {
		panic("filter: " + rest)
	}
	return b
}

func encText(f string) ([]byte, string) {
	if !strings.HasPrefix(f, "(") {
		panic("filter: " + f)
	}
	f = f[1:]
	switch f[0] {
	case '&', '|', '!':
		kind := map[byte]byte{'&': 0, '|': 1, '!': 2}[f[0]]
		f = f[1:]
		var parts []byte
		for strings.HasPrefix(f, "(") {
			var p []byte
			p, f = encText(f)
			parts = append(parts, p...)
		}
		return enc(classContext|constructed|kind, parts), strings.TrimPrefix(f, ")")
	}
	i := strings.Index(f, ")")
	item, rest := f[:i], f[i+1:]
	eq := strings.Index(item, "=")
	attr, val := item[:eq], item[eq+1:]
	if strings.HasSuffix(attr, ">") || strings.HasSuffix(attr, "<") { // >= and <=
		kind := byte(5)
		if strings.HasSuffix(attr, "<") {
			kind = 6
		}
		return enc(classContext|constructed|kind, join(encStr(attr[:len(attr)-1]), encStr(val))), rest
	}
	switch {
	case val == "*":
		return enc(classContext|7, []byte(attr)), rest
	case strings.Contains(val, "*"):
		ps := strings.Split(val, "*")
		var subs []byte
		if ps[0] != "" {
			subs = append(subs, enc(classContext|0, []byte(ps[0]))...)
		}
		for _, a := range ps[1 : len(ps)-1] {
			subs = append(subs, enc(classContext|1, []byte(a))...)
		}
		if ps[len(ps)-1] != "" {
			subs = append(subs, enc(classContext|2, []byte(ps[len(ps)-1]))...)
		}
		return enc(classContext|constructed|4, join(encStr(attr), encSeq(subs))), rest
	default:
		return enc(classContext|constructed|3, join(encStr(attr), encStr(val))), rest
	}
}

// ---- a fake directory ----

type fakeDir struct{ people []Person }

func (fakeDir) BaseDN() string { return "dc=auth,dc=office,dc=lan" }
func (fakeDir) Domain() string { return "auth.office.lan" }
func (d fakeDir) People() []Person {
	return []Person{
		{Name: "alice", DisplayName: "Alice A", Mails: []string{"alice@example.com", "alice@other.com"}, UID: 1000, UUID: "u-alice", Groups: []string{"staff", "keelauth-admins"}},
		{Name: "bob", DisplayName: "Bob", Mails: []string{"bob@example.com"}, UID: 1001, UUID: "u-bob", Groups: []string{"staff"}},
		{Name: "carol", UID: 1002, UUID: "u-carol", Groups: []string{}},
	}
}
func (fakeDir) Groups() []Group {
	return []Group{{Name: "staff", Description: "everybody", Members: []string{"alice", "bob"}, GID: 2000, UUID: "g-staff"},
		{Name: "keelauth-admins", Members: []string{"alice"}, GID: 2001}}
}
func (fakeDir) CheckPassword(name, pw string) bool {
	return name == "alice" && pw == "alice-pw" || name == "bob" && pw == "bob-pw"
}
func (fakeDir) CheckToken(t string) (string, bool) {
	if t == "kad_printer2" {
		return "printer2", true
	}
	return "", false
}

func newClient(t *testing.T) (*client, *Server) {
	t.Helper()
	s := &Server{Dir: fakeDir{}, Timeout: 5 * time.Second}
	a, b := net.Pipe()
	go s.ServeConn(pipeConn{b})
	return &client{c: a}, s
}

// pipeConn gives net.Pipe a RemoteAddr with a host.
type pipeConn struct{ net.Conn }

func (pipeConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4(192, 0, 2, 7), Port: 4000} }

func TestBindAndSearch(t *testing.T) {
	cl, _ := newClient(t)
	defer cl.c.Close()
	if code, _ := cl.search("dc=auth,dc=office,dc=lan", scopeSubtree, "(class=person)"); code != rcInsufficientAccess {
		t.Fatalf("anonymous search: %d", code)
	}
	if code, _ := cl.bind("name=alice,dc=auth,dc=office,dc=lan", "wrong"); code != rcInvalidCredentials {
		t.Fatalf("wrong password: %d", code)
	}
	if code, _ := cl.bind("name=alice,dc=auth,dc=office,dc=lan", ""); code != rcInvalidCredentials {
		t.Fatalf("empty password with a name: %d", code)
	}
	if code, _ := cl.bind("name=alice,dc=other", "alice-pw"); code != rcInvalidCredentials {
		t.Fatalf("other base: %d", code)
	}
	for _, dn := range []string{"name=alice,dc=auth,dc=office,dc=lan", "uid=Alice, dc=auth, dc=office, dc=lan", "spn=alice@auth.office.lan,dc=auth,dc=office,dc=lan", "alice", "alice@auth.office.lan"} {
		if code, msg := cl.bind(dn, "alice-pw"); code != rcSuccess {
			t.Fatalf("bind %q: %d %s", dn, code, msg)
		}
	}
	if w := cl.whoami(); w != "dn:name=alice,dc=auth,dc=office,dc=lan" {
		t.Fatalf("whoami: %q", w)
	}
	code, rs := cl.search("dc=auth,dc=office,dc=lan", scopeSubtree, "(class=person)", "name", "mail", "displayname", "memberof", "uidnumber")
	if code != rcSuccess || len(rs) != 3 {
		t.Fatalf("persons: %d %v", code, rs)
	}
	a := rs[0]
	if a.dn != "name=alice,dc=auth,dc=office,dc=lan" || len(a.attrs["mail"]) != 2 || a.attrs["displayname"][0] != "Alice A" ||
		strings.Join(a.attrs["memberof"], " ") != "name=keelauth-admins,dc=auth,dc=office,dc=lan name=staff,dc=auth,dc=office,dc=lan" || a.attrs["uidnumber"][0] != "1000" {
		t.Fatalf("alice: %+v", a)
	}
	if _, ok := a.attrs["objectclass"]; ok {
		t.Fatal("objectclass came although not asked for")
	}
	// Dovecot / Stalwart style lookups
	for _, c := range []struct {
		f string
		n int
	}{
		{"(&(class=person)(|(name=bob)(mail=bob)))", 1},
		{"(&(class=person)(|(name=x)(mail=bob@example.com)))", 1},
		{"(&(class=person)(mail=*@example.com))", 2},
		{"(&(class=person)(|(mail=*@example.com)(mail=*@other.com)))", 2},
		{"(&(objectClass=person)(uid=CAROL))", 1},
		{"(mail=*)", 2},
		{"(!(mail=*))", 4}, // root, base, carol, and both groups? groups have no mail: root, base, carol, staff, admins = 5 minus... see below
		{"(class=group)", 2},
		{"(&(class=group)(member=name=alice,dc=auth,dc=office,dc=lan))", 2},
		{"(memberof=name=staff,dc=auth,dc=office,dc=lan)", 2},
		{"(uidnumber>=1001)", 2},
	} {
		code, rs := cl.search("dc=auth,dc=office,dc=lan", scopeSubtree, c.f)
		want := c.n
		if c.f == "(!(mail=*))" {
			want = 4 // base, carol, staff, keelauth-admins (the root DSE is outside the base)
		}
		if code != rcSuccess || len(rs) != want {
			t.Errorf("%s: %d, %d entries (want %d)", c.f, code, len(rs), want)
		}
	}
	// groups and scopes
	_, gs := cl.search("name=staff,dc=auth,dc=office,dc=lan", scopeBase, "(objectclass=*)")
	if len(gs) != 1 || strings.Join(gs[0].attrs["member"], " ") != "name=alice,dc=auth,dc=office,dc=lan name=bob,dc=auth,dc=office,dc=lan" || gs[0].attrs["gidnumber"][0] != "2000" {
		t.Fatalf("staff: %+v", gs)
	}
	if _, rs := cl.search("dc=auth,dc=office,dc=lan", scopeOneLevel, "(objectclass=*)"); len(rs) != 5 {
		t.Fatalf("one level: %d entries", len(rs))
	}
	if _, rs := cl.search("", scopeBase, "(objectclass=*)", "namingcontexts"); len(rs) != 1 || rs[0].attrs["namingcontexts"][0] != "dc=auth,dc=office,dc=lan" {
		t.Fatalf("root DSE: %+v", rs)
	}
	if code, _ := cl.search("dc=nowhere", scopeSubtree, "(objectclass=*)"); code != rcNoSuchObject {
		t.Fatalf("unknown base: %d", code)
	}
	// unbind ends the connection
	cl.send(enc(classApplication|appUnbindRequest, nil))
	if _, err := cl.read(); !errors.Is(err, io.EOF) {
		t.Fatalf("after unbind: %v", err)
	}
}

func TestDeviceTokenAndThrottle(t *testing.T) {
	cl, s := newClient(t)
	defer cl.c.Close()
	if code, _ := cl.bind("dn=token", "kad_wrong"); code != rcInvalidCredentials {
		t.Fatalf("wrong token: %d", code)
	}
	if code, _ := cl.bind("dn=token", "kad_printer2"); code != rcSuccess {
		t.Fatalf("token: %d", code)
	}
	if w := cl.whoami(); w != "dn:name=printer2,dc=auth,dc=office,dc=lan" {
		t.Fatalf("whoami: %q", w)
	}
	if code, rs := cl.search("dc=auth,dc=office,dc=lan", scopeSubtree, "(name=alice)", "mail"); code != rcSuccess || len(rs) != 1 || len(rs[0].attrs["mail"]) != 2 {
		t.Fatalf("device reads mail: %d %+v", code, rs)
	}
	// five failures for bob: the sixth try is refused without a look at the password
	for i := 0; i < 5; i++ {
		cl.bind("bob", "nope")
	}
	if code, msg := cl.bind("bob", "bob-pw"); code != rcInvalidCredentials || !strings.Contains(msg, "too many") {
		t.Fatalf("throttled bind: %d %q", code, msg)
	}
	s.lim.OK("192.0.2.7", "bob")
	if code, _ := cl.bind("bob", "bob-pw"); code != rcSuccess {
		t.Fatalf("after the block: %d", code)
	}
}

func TestWritesRefused(t *testing.T) {
	cl, _ := newClient(t)
	defer cl.c.Close()
	cl.bind("alice", "alice-pw")
	cl.send(encApp(8, encStr("name=alice,dc=auth,dc=office,dc=lan"), encSeq())) // ModifyRequest
	op, err := cl.read()
	if err != nil || op.tag&^constructed&^classApplication != 9 {
		t.Fatalf("modify response: %v %x", err, op.tag)
	}
	parts, _ := op.children()
	if code, _ := parts[0].int(); code != rcUnwillingToPerform {
		t.Fatalf("modify: %d", code)
	}
}

// TestRealServer talks to a running keelAuth (KEELAUTH_LDAP=host:port, KEELAUTH_USER,
// KEELAUTH_PW): bind as the user, list the persons and groups. Skipped without the address.
func TestRealServer(t *testing.T) {
	addr := os.Getenv("KEELAUTH_LDAP")
	if addr == "" {
		t.Skip("KEELAUTH_LDAP not set")
	}
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cl := &client{c: c}
	if code, _ := cl.search("", scopeSubtree, "(class=person)"); code != rcInsufficientAccess {
		t.Fatalf("anonymous search: %d", code)
	}
	if code, msg := cl.bind(os.Getenv("KEELAUTH_USER"), os.Getenv("KEELAUTH_PW")); code != rcSuccess {
		t.Fatalf("bind: %d %s", code, msg)
	}
	t.Logf("whoami: %s", cl.whoami())
	_, rs := cl.search("", scopeBase, "(objectclass=*)", "namingcontexts")
	base := rs[0].attrs["namingcontexts"][0]
	code, ps := cl.search(base, scopeSubtree, "(class=person)", "name", "mail", "memberof", "uidnumber")
	if code != rcSuccess || len(ps) == 0 {
		t.Fatalf("persons: %d %d", code, len(ps))
	}
	for _, p := range ps {
		t.Logf("person %s mail=%v memberof=%v uid=%v", p.dn, p.attrs["mail"], p.attrs["memberof"], p.attrs["uidnumber"])
	}
	code, gs := cl.search(base, scopeSubtree, "(class=group)", "name", "member")
	if code != rcSuccess {
		t.Fatalf("groups: %d", code)
	}
	for _, g := range gs {
		t.Logf("group %s member=%v", g.dn, g.attrs["member"])
	}
}
