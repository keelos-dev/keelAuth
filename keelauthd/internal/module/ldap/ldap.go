package ldap

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"keelauth/internal/module/limit"
)

// Directory is what the server reads: keelauthd's view of the account store.
type Directory interface {
	BaseDN() string // dc=auth,dc=office,dc=lan
	Domain() string // auth.office.lan
	People() []Person
	Groups() []Group
	// CheckPassword: an enabled person with this password (a bind).
	CheckPassword(name, password string) bool
	// CheckToken: the device account whose current token this is (a "dn=token" bind).
	CheckToken(token string) (device string, ok bool)
}

// Person is a user as the directory shows it.
type Person struct {
	Name        string
	DisplayName string
	Mails       []string
	UID         int
	UUID        string
	Groups      []string // the groups it is in (direct and through nested groups)
}

// Group is a group as the directory shows it.
type Group struct {
	Name        string
	Description string
	Members     []string // persons (nested groups flattened)
	GID         int
	UUID        string
}

// LDAP result codes.
const (
	rcSuccess                = 0
	rcOperationsError        = 1
	rcProtocolError          = 2
	rcSizeLimitExceeded      = 4
	rcAuthMethodNotSupported = 7
	rcNoSuchObject           = 32
	rcInvalidCredentials     = 49
	rcInsufficientAccess     = 50
	rcUnwillingToPerform     = 53

	appBindRequest     = 0
	appBindResponse    = 1
	appUnbindRequest   = 2
	appSearchRequest   = 3
	appSearchEntry     = 4
	appSearchDone      = 5
	appAbandonRequest  = 16
	appExtendedRequest = 23
	appExtendedResp    = 24

	scopeBase     = 0
	scopeOneLevel = 1
	scopeSubtree  = 2

	maxMessage = 1 << 20 // one request at most 1 MiB
	maxEntries = 5000    // one search answers at most this many entries
	whoamiOID  = "1.3.6.1.4.1.4203.1.11.3"
)

// Server answers LDAP on connections keelauthd hands it (Serve on a TLS listener).
type Server struct {
	Dir Directory
	Log *log.Logger
	// Timeout: a connection idle this long is closed (0 = 10 minutes).
	Timeout time.Duration

	lim limit.Limiter
	mu  sync.Mutex
	ln  net.Listener
}

// Serve accepts connections until the listener closes.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(c)
	}
}

// Close stops accepting.
func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
	}
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log.Printf("ldap: "+format, a...)
	}
}

// conn is one connection's state.
type conn struct {
	s     *Server
	c     net.Conn
	addr  string
	bound string // "" anonymous; else who ("alice", "device:printer1")
}

// ServeConn handles one connection (closed when it returns).
func (s *Server) ServeConn(c net.Conn) {
	defer c.Close()
	timeout := s.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
	cn := &conn{s: s, c: c, addr: host}
	for {
		c.SetDeadline(time.Now().Add(timeout))
		msg, err := readMessage(c)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !isTimeout(err) {
				s.logf("%s: %v", host, err)
			}
			return
		}
		if !cn.handle(msg) {
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// readMessage reads one LDAPMessage (its outer SEQUENCE) from the connection.
func readMessage(r io.Reader) (elem, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return elem{}, err
	}
	if head[0] != tagSequence {
		return elem{}, fmt.Errorf("%w: not an LDAP message", errBER)
	}
	n := int(head[1])
	var lenBytes []byte
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 {
			return elem{}, fmt.Errorf("%w: length", errBER)
		}
		lenBytes = make([]byte, k)
		if _, err := io.ReadFull(r, lenBytes); err != nil {
			return elem{}, err
		}
		n = 0
		for _, c := range lenBytes {
			n = n<<8 | int(c)
		}
	}
	if n > maxMessage {
		return elem{}, fmt.Errorf("message of %d bytes refused", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return elem{}, err
	}
	return elem{tag: tagSequence, val: body}, nil
}

// handle answers one message; false: the connection ends (unbind, protocol error).
func (cn *conn) handle(msg elem) bool {
	parts, err := msg.children()
	if err != nil || len(parts) < 2 {
		return false
	}
	id, err := parts[0].int()
	if err != nil {
		return false
	}
	op := parts[1]
	if op.tag&0xc0 != classApplication {
		return false
	}
	switch op.tag &^ constructed &^ classApplication {
	case appBindRequest:
		return cn.bind(id, op)
	case appUnbindRequest:
		return false
	case appSearchRequest:
		return cn.search(id, op)
	case appAbandonRequest:
		return true
	case appExtendedRequest:
		return cn.extended(id, op)
	default:
		// a write (add, modify, delete, modify DN) or compare: not here
		n := op.tag &^ constructed &^ classApplication
		cn.send(id, encApp(n+1, result(rcUnwillingToPerform, "", "keelAuth's LDAP is read-only")))
		return true
	}
}

func result(code int, matched, msg string) []byte {
	return join(encEnum(code), encStr(matched), encStr(msg))
}

func (cn *conn) send(id int, op []byte) error {
	_, err := cn.c.Write(encSeq(encInt(tagInteger, id), op))
	return err
}

// ---- bind ----

func (cn *conn) bind(id int, op elem) bool {
	parts, err := op.children()
	if err != nil || len(parts) < 3 {
		return false
	}
	name := strings.TrimSpace(parts[1].str())
	auth := parts[2]
	if auth.tag != classContext|0 { // simple [0]; SASL [3] and anything else
		cn.send(id, encApp(appBindResponse, result(rcAuthMethodNotSupported, "", "simple bind only")))
		return true
	}
	pw := auth.str()
	cn.bound = ""
	if name == "" && pw == "" { // anonymous: allowed in, reads nothing
		cn.send(id, encApp(appBindResponse, result(rcSuccess, "", "")))
		return true
	}
	if pw == "" { // an unauthenticated bind (a name without a password) is a mistake, not anonymous
		cn.send(id, encApp(appBindResponse, result(rcInvalidCredentials, "", "no password")))
		return true
	}
	who := strings.ToLower(name)
	if wait := cn.s.lim.Blocked(cn.addr, who); wait > 0 {
		cn.send(id, encApp(appBindResponse, result(rcInvalidCredentials, "", fmt.Sprintf("too many failed binds: try again in %d s", int(wait.Seconds())+1))))
		return true
	}
	ok := false
	switch {
	case strings.EqualFold(name, "dn=token"):
		if dev, good := cn.s.Dir.CheckToken(pw); good {
			cn.bound, ok = "device:"+dev, true
		}
	default:
		if u := cn.bindName(name); u != "" && cn.s.Dir.CheckPassword(u, pw) {
			cn.bound, ok = u, true
		}
	}
	if !ok {
		cn.s.lim.Failed(cn.addr, who)
		cn.s.logf("bind %s from %s: invalid credentials", name, cn.addr)
		cn.send(id, encApp(appBindResponse, result(rcInvalidCredentials, "", "")))
		return true
	}
	cn.s.lim.OK(cn.addr, who)
	cn.send(id, encApp(appBindResponse, result(rcSuccess, "", "")))
	return true
}

// bindName is the user a bind DN names: name=alice,<base>, uid=alice,…, cn=alice,…,
// spn=alice@domain,…, alice@domain, or just alice. "" when it is none of these.
func (cn *conn) bindName(dn string) string {
	base := normDN(cn.s.Dir.BaseDN())
	v := strings.TrimSpace(dn)
	if i := strings.Index(v, ","); i >= 0 {
		if normDN(v[i+1:]) != base {
			return ""
		}
		v = v[:i]
	}
	if i := strings.Index(v, "="); i >= 0 {
		attr := strings.ToLower(strings.TrimSpace(v[:i]))
		switch attr {
		case "name", "uid", "cn", "spn":
		default:
			return ""
		}
		v = v[i+1:]
	}
	v = strings.TrimSpace(v)
	if i := strings.Index(v, "@"); i >= 0 {
		if !strings.EqualFold(v[i+1:], cn.s.Dir.Domain()) {
			return ""
		}
		v = v[:i]
	}
	return strings.ToLower(v)
}

// ---- extended ----

func (cn *conn) extended(id int, op elem) bool {
	parts, err := op.children()
	if err != nil || len(parts) < 1 {
		return false
	}
	if parts[0].str() == whoamiOID {
		who := ""
		switch {
		case cn.bound == "":
		case strings.HasPrefix(cn.bound, "device:"):
			who = "dn:name=" + strings.TrimPrefix(cn.bound, "device:") + "," + cn.s.Dir.BaseDN()
		default:
			who = "dn:name=" + cn.bound + "," + cn.s.Dir.BaseDN()
		}
		cn.send(id, encApp(appExtendedResp, join(result(rcSuccess, "", ""), enc(classContext|11, []byte(who)))))
		return true
	}
	cn.send(id, encApp(appExtendedResp, result(rcProtocolError, "", "unknown extended operation")))
	return true
}

// ---- search ----

func (cn *conn) search(id int, op elem) bool {
	parts, err := op.children()
	if err != nil || len(parts) < 8 {
		return false
	}
	base := normDN(parts[0].str())
	scope, _ := parts[1].int()
	sizeLimit, _ := parts[3].int()
	typesOnly := parts[5].bool()
	f, err := parseFilter(parts[6])
	if err != nil {
		cn.send(id, encApp(appSearchDone, result(rcProtocolError, "", err.Error())))
		return true
	}
	var attrs []string
	if as, err := parts[7].children(); err == nil {
		for _, a := range as {
			attrs = append(attrs, strings.ToLower(a.str()))
		}
	}
	if cn.bound == "" {
		cn.send(id, encApp(appSearchDone, result(rcInsufficientAccess, "", "bind first: anonymous reads are off")))
		return true
	}
	baseDN := normDN(cn.s.Dir.BaseDN())
	if base != "" && base != baseDN && !strings.HasSuffix(base, ","+baseDN) {
		cn.send(id, encApp(appSearchDone, result(rcNoSuchObject, "", "")))
		return true
	}
	limit := maxEntries
	if sizeLimit > 0 && sizeLimit < limit {
		limit = sizeLimit
	}
	n := 0
	for _, e := range cn.s.entries() {
		if !inScope(e.dn, base, baseDN, scope) || !f.match(e) {
			continue
		}
		if n == limit {
			cn.send(id, encApp(appSearchDone, result(rcSizeLimitExceeded, "", "")))
			return true
		}
		n++
		if err := cn.send(id, encApp(appSearchEntry, e.encode(attrs, typesOnly))); err != nil {
			return false
		}
	}
	cn.send(id, encApp(appSearchDone, result(rcSuccess, "", "")))
	return true
}

// normDN: lower case, no spaces around the commas (DNs here are simple).
func normDN(dn string) string {
	parts := strings.Split(strings.TrimSpace(dn), ",")
	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return strings.ToLower(strings.Join(parts, ","))
}

// inScope: the entry's DN (normalized) is what the search asks for. The base "" (the root)
// with scope base is the root DSE; with a wider scope it means everything.
func inScope(dn, base, baseDN string, scope int) bool {
	switch scope {
	case scopeBase:
		return dn == base
	case scopeOneLevel:
		if base == "" {
			return dn == baseDN
		}
		return strings.HasSuffix(dn, ","+base) && !strings.Contains(strings.TrimSuffix(dn, ","+base), ",")
	default:
		return base == "" || dn == base || strings.HasSuffix(dn, ","+base)
	}
}

// ---- entries ----

// entry is one object: its DN and attributes (names lower case, in order).
type entry struct {
	dn    string // normalized (lower case)
	shown string // as sent
	attrs map[string][]string
	order []string
}

func newEntry(dn string) *entry {
	return &entry{dn: normDN(dn), shown: dn, attrs: map[string][]string{}}
}

func (e *entry) add(name string, vals ...string) {
	name = strings.ToLower(name)
	if _, ok := e.attrs[name]; !ok {
		e.order = append(e.order, name)
	}
	e.attrs[name] = append(e.attrs[name], vals...)
}

// encode is the SearchResultEntry's content for the attributes asked for ("*" / none = all,
// "1.1" = none, "+" = the operational ones, which we have none of beyond entryuuid).
func (e *entry) encode(attrs []string, typesOnly bool) []byte {
	want := map[string]bool{}
	all := len(attrs) == 0
	for _, a := range attrs {
		switch a {
		case "*":
			all = true
		case "1.1", "+":
		default:
			want[a] = true
		}
	}
	var list []byte
	for _, n := range e.order {
		if !all && !want[n] {
			continue
		}
		var vals []byte
		if !typesOnly {
			for _, v := range e.attrs[n] {
				vals = append(vals, encStr(v)...)
			}
		}
		list = append(list, encSeq(encStr(n), encSet(vals))...)
	}
	return join(encStr(e.shown), encSeq(list))
}

// entries is the whole tree as of now: the root DSE, the base, every person, every group.
func (s *Server) entries() []*entry {
	base := s.Dir.BaseDN()
	domain := s.Dir.Domain()
	root := newEntry("")
	root.add("objectclass", "top")
	root.add("namingcontexts", base)
	root.add("supportedldapversion", "3")
	root.add("supportedextension", whoamiOID)
	root.add("vendorname", "keelAuth")
	top := newEntry(base)
	top.add("objectclass", "top", "domain", "object")
	top.add("dc", strings.SplitN(domain, ".", 2)[0])
	top.add("domain", domain)
	out := []*entry{root, top}
	groups := s.Dir.Groups()
	byUser := map[string][]string{}
	for _, g := range groups {
		for _, m := range g.Members {
			byUser[m] = append(byUser[m], g.Name)
		}
	}
	people := s.Dir.People()
	sort.Slice(people, func(i, j int) bool { return people[i].Name < people[j].Name })
	for _, p := range people {
		e := newEntry("name=" + p.Name + "," + base)
		e.add("objectclass", "person", "account", "posixaccount", "memberof", "object")
		e.add("class", "person", "account", "posixaccount", "memberof", "object")
		e.add("name", p.Name)
		e.add("uid", p.Name)
		e.add("cn", p.Name)
		e.add("spn", p.Name+"@"+domain)
		if p.DisplayName != "" {
			e.add("displayname", p.DisplayName)
		}
		if len(p.Mails) > 0 {
			e.add("mail", p.Mails...)
		}
		gs := p.Groups
		if gs == nil {
			gs = byUser[p.Name]
		}
		sort.Strings(gs)
		for _, g := range gs {
			e.add("memberof", "name="+g+","+base)
		}
		e.add("uidnumber", strconv.Itoa(p.UID))
		e.add("gidnumber", strconv.Itoa(p.UID))
		e.add("homedirectory", "/home/"+p.Name)
		e.add("loginshell", "/bin/sh")
		if p.UUID != "" {
			e.add("entryuuid", p.UUID)
			e.add("uuid", p.UUID)
		}
		out = append(out, e)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Name < groups[j].Name })
	for _, g := range groups {
		e := newEntry("name=" + g.Name + "," + base)
		e.add("objectclass", "group", "posixgroup", "object")
		e.add("class", "group", "posixgroup", "object")
		e.add("name", g.Name)
		e.add("cn", g.Name)
		e.add("spn", g.Name+"@"+domain)
		if g.Description != "" {
			e.add("description", g.Description)
		}
		ms := append([]string(nil), g.Members...)
		sort.Strings(ms)
		for _, m := range ms {
			e.add("member", "name="+m+","+base)
		}
		if len(ms) > 0 {
			e.add("memberuid", ms...)
		}
		e.add("gidnumber", strconv.Itoa(g.GID))
		if g.UUID != "" {
			e.add("entryuuid", g.UUID)
			e.add("uuid", g.UUID)
		}
		out = append(out, e)
	}
	return out
}

// ---- filters ----

type filter struct {
	kind byte // the context tag number: 0 and, 1 or, 2 not, 3 equality, 4 substrings, 5 ge, 6 le, 7 present, 8 approx, 9 extensible
	subs []*filter
	attr string
	val  string
	// substrings: initial, any…, final ("" = none); anyParts in order
	initial, final string
	anyParts       []string
}

func parseFilter(e elem) (*filter, error) {
	if e.tag&0xc0 != classContext {
		return nil, errors.New("filter: bad tag")
	}
	f := &filter{kind: e.tag &^ constructed &^ classContext}
	switch f.kind {
	case 0, 1: // and, or
		cs, err := e.children()
		if err != nil {
			return nil, err
		}
		for _, c := range cs {
			sf, err := parseFilter(c)
			if err != nil {
				return nil, err
			}
			f.subs = append(f.subs, sf)
		}
	case 2: // not
		cs, err := e.children()
		if err != nil || len(cs) != 1 {
			return nil, errors.New("filter: not")
		}
		sf, err := parseFilter(cs[0])
		if err != nil {
			return nil, err
		}
		f.subs = []*filter{sf}
	case 3, 5, 6, 8: // attr=value and friends: AttributeValueAssertion
		cs, err := e.children()
		if err != nil || len(cs) != 2 {
			return nil, errors.New("filter: assertion")
		}
		f.attr, f.val = strings.ToLower(cs[0].str()), cs[1].str()
	case 4: // substrings
		cs, err := e.children()
		if err != nil || len(cs) != 2 {
			return nil, errors.New("filter: substrings")
		}
		f.attr = strings.ToLower(cs[0].str())
		ss, err := cs[1].children()
		if err != nil {
			return nil, err
		}
		for _, s := range ss {
			switch s.tag {
			case classContext | 0:
				f.initial = s.str()
			case classContext | 1:
				f.anyParts = append(f.anyParts, s.str())
			case classContext | 2:
				f.final = s.str()
			}
		}
	case 7: // present
		f.attr = strings.ToLower(e.str())
	case 9: // extensible match: not supported, matches nothing
	default:
		return nil, errors.New("filter: unknown kind")
	}
	return f, nil
}

// match evaluates the filter on an entry: attribute names and values compared without
// regard to case ("class" is what Kanidm calls objectclass; both work).
func (f *filter) match(e *entry) bool {
	switch f.kind {
	case 0:
		for _, s := range f.subs {
			if !s.match(e) {
				return false
			}
		}
		return true
	case 1:
		for _, s := range f.subs {
			if s.match(e) {
				return true
			}
		}
		return false
	case 2:
		return !f.subs[0].match(e)
	case 7:
		_, ok := e.attrs[f.attr]
		return ok
	case 3, 8:
		for _, v := range e.attrs[f.attr] {
			if strings.EqualFold(v, f.val) {
				return true
			}
		}
		return false
	case 5, 6:
		for _, v := range e.attrs[f.attr] {
			c := compare(v, f.val)
			if (f.kind == 5 && c >= 0) || (f.kind == 6 && c <= 0) {
				return true
			}
		}
		return false
	case 4:
		for _, v := range e.attrs[f.attr] {
			if f.substr(strings.ToLower(v)) {
				return true
			}
		}
		return false
	}
	return false
}

func (f *filter) substr(v string) bool {
	if f.initial != "" {
		if !strings.HasPrefix(v, strings.ToLower(f.initial)) {
			return false
		}
		v = v[len(f.initial):]
	}
	if f.final != "" {
		fin := strings.ToLower(f.final)
		if !strings.HasSuffix(v, fin) {
			return false
		}
		v = v[:len(v)-len(fin)]
	}
	for _, a := range f.anyParts {
		i := strings.Index(v, strings.ToLower(a))
		if i < 0 {
			return false
		}
		v = v[i+len(a):]
	}
	return true
}

func compare(a, b string) int {
	if x, err1 := strconv.Atoi(a); err1 == nil {
		if y, err2 := strconv.Atoi(b); err2 == nil {
			return x - y
		}
	}
	return strings.Compare(strings.ToLower(a), strings.ToLower(b))
}
