package ldap

// This file: the little LDAP client keelAuth needs to read another directory once (docs/07:
// importing the accounts of a Windows AD). Simple bind, subtree search with paging, TLS from
// the first byte (636) or by StartTLS (389); nothing is ever written to the other side.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	oidStartTLS = "1.3.6.1.4.1.1466.20037"
	oidPaging   = "1.2.840.113556.1.4.319" // RFC 2696
	pageSize    = 500                      // AD gives at most 1000 an answer

	upstreamTimeout = 30 * time.Second
)

// ErrUpstreamLogin: the other directory refused the name and password.
var ErrUpstreamLogin = errors.New("the directory refused this account and password")

// PinError: the other directory's certificate is not the one the administrator accepted
// (or none was accepted yet). Got is the fingerprint it showed.
type PinError struct{ Got string }

func (e *PinError) Error() string { return "certificate fingerprint " + e.Got + " was not accepted" }

// Upstream is one connection to another directory.
type Upstream struct {
	conn        net.Conn
	id          int
	Fingerprint string // SHA-256 of the certificate the server showed, hex
	StartTLS    bool   // true: port 389 with StartTLS; false: TLS from the start
}

// Entry is one search answer. Attribute names are lower case.
type Entry struct {
	DN    string
	Attrs map[string][]string
}

// First is the attribute's first value, or "".
func (e Entry) First(attr string) string {
	if v := e.Attrs[strings.ToLower(attr)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Filter is an encoded search filter; make one with And, Eq, Present.
type Filter []byte

func And(fs ...Filter) Filter {
	var b []byte
	for _, f := range fs {
		b = append(b, f...)
	}
	return enc(classContext|constructed|0, b)
}
func Eq(attr, value string) Filter {
	return enc(classContext|constructed|3, join(encStr(attr), encStr(value)))
}
func Present(attr string) Filter { return enc(classContext|7, []byte(attr)) }

// DialUpstream connects to address ("host", "host:port" or an IP). Without a port it tries
// 636 (TLS) and then 389 with StartTLS; with one that is neither's, TLS and then StartTLS there; a password never crosses an open connection. The
// certificate is not checked against any CA (an AD's is its own): pin is the SHA-256
// fingerprint the administrator accepted, and a different or missing one gives *PinError
// with the fingerprint seen.
func DialUpstream(ctx context.Context, address, pin string) (*Upstream, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = strings.Trim(address, "[]"), ""
	}
	type try struct {
		port     string
		startTLS bool
	}
	tries := []try{{"636", false}, {"389", true}}
	switch port {
	case "":
	case "636", "3269":
		tries = []try{{port, false}}
	case "389", "3268":
		tries = []try{{port, true}}
	default: // a forwarded port: whichever of the two it answers
		tries = []try{{port, false}, {port, true}}
	}
	var firstErr error
	for _, t := range tries {
		u, err := dialOne(ctx, host, t.port, t.startTLS)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if want := normFingerprint(pin); want == "" || want != u.Fingerprint {
			u.Close()
			return nil, &PinError{Got: u.Fingerprint}
		}
		return u, nil
	}
	return nil, firstErr
}

func normFingerprint(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			return r
		}
		return -1
	}, strings.ToLower(s))
}

func dialOne(ctx context.Context, host, port string, startTLS bool) (*Upstream, error) {
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	u := &Upstream{conn: raw, StartTLS: startTLS}
	if startTLS {
		op, err := u.roundTrip(enc(classApplication|constructed|23, enc(classContext|0, []byte(oidStartTLS))), nil)
		if err == nil {
			err = resultError(op, classApplication|constructed|24)
		}
		if err != nil {
			raw.Close()
			return nil, fmt.Errorf("StartTLS on port %s: %w", port, err)
		}
	}
	// The certificate is judged by its fingerprint (the caller's pin), not by a CA.
	tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host})
	raw.SetDeadline(time.Now().Add(upstreamTimeout))
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS on port %s: %w", port, err)
	}
	certs := tc.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		tc.Close()
		return nil, errors.New("the directory showed no certificate")
	}
	sum := sha256.Sum256(certs[0].Raw)
	u.conn, u.Fingerprint = tc, hex.EncodeToString(sum[:])
	return u, nil
}

func (u *Upstream) Close() error { return u.conn.Close() }

// send writes one request; controls may be nil.
func (u *Upstream) send(op, controls []byte) error {
	u.id++
	msg := join(encInt(tagInteger, u.id), op)
	if controls != nil {
		msg = append(msg, enc(classContext|constructed|0, controls)...)
	}
	u.conn.SetDeadline(time.Now().Add(upstreamTimeout))
	_, err := u.conn.Write(encSeq(msg))
	return err
}

// recv reads the next answer to the current request: its operation and its controls.
func (u *Upstream) recv() (op elem, controls []elem, err error) {
	for {
		u.conn.SetDeadline(time.Now().Add(upstreamTimeout))
		m, err := readMessage(u.conn)
		if err != nil {
			return elem{}, nil, err
		}
		parts, err := m.children()
		if err != nil || len(parts) < 2 {
			return elem{}, nil, errBER
		}
		if id, err := parts[0].int(); err != nil || id != u.id {
			continue // an unsolicited notice or a late answer
		}
		if len(parts) > 2 && parts[2].tag == classContext|constructed|0 {
			if controls, err = parts[2].children(); err != nil {
				return elem{}, nil, err
			}
		}
		return parts[1], controls, nil
	}
}

func (u *Upstream) roundTrip(op, controls []byte) (elem, error) {
	if err := u.send(op, controls); err != nil {
		return elem{}, err
	}
	e, _, err := u.recv()
	return e, err
}

// ResultError is an LDAP result other than success.
type ResultError struct {
	Code    int
	Message string
}

func (e *ResultError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("LDAP result %d", e.Code)
	}
	return fmt.Sprintf("LDAP result %d: %s", e.Code, e.Message)
}

// resultError reads the LDAPResult in op (which must have the tag want): nil for success.
func resultError(op elem, want byte) error {
	if op.tag != want {
		return fmt.Errorf("%w: answer with tag %#x", errBER, op.tag)
	}
	parts, err := op.children()
	if err != nil || len(parts) < 3 {
		return errBER
	}
	code, err := parts[0].int()
	if err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	return &ResultError{Code: code, Message: strings.TrimRight(parts[2].str(), "\x00")}
}

// Bind is a simple bind. For an AD the name is user@domain or DOMAIN\user (or a DN).
func (u *Upstream) Bind(name, password string) error {
	if password == "" {
		return ErrUpstreamLogin // an empty password would be an anonymous bind that "succeeds"
	}
	op, err := u.roundTrip(encApp(0, encInt(tagInteger, 3), encStr(name), enc(classContext|0, []byte(password))), nil)
	if err != nil {
		return err
	}
	err = resultError(op, classApplication|constructed|1)
	var re *ResultError
	if errors.As(err, &re) && re.Code == 49 {
		return ErrUpstreamLogin
	}
	return err
}

// Search walks base (the entry itself when baseOnly, else its whole subtree) and calls each
// for every entry matching filter, with the attributes asked for. It pages, so a directory's
// answer limit does not cut the list short.
func (u *Upstream) Search(base string, baseOnly bool, filter Filter, attrs []string, each func(Entry) error) error {
	scope := 2
	if baseOnly {
		scope = 0
	}
	var want []byte
	for _, a := range attrs {
		want = append(want, encStr(a)...)
	}
	req := encApp(3, encStr(base), encEnum(scope), encEnum(0), encInt(tagInteger, 0), encInt(tagInteger, 0),
		encBool(false), filter, encSeq(want))
	cookie := ""
	for {
		page := encSeq(encStr(oidPaging), encBool(false), encStr(string(encSeq(encInt(tagInteger, pageSize), encStr(cookie)))))
		if baseOnly {
			page = nil
		}
		if err := u.send(req, page); err != nil {
			return err
		}
		cookie = ""
		for {
			op, controls, err := u.recv()
			if err != nil {
				return err
			}
			if op.tag == classApplication|constructed|4 {
				e, err := parseEntry(op)
				if err != nil {
					return err
				}
				if err := each(e); err != nil {
					return err
				}
				continue
			}
			if op.tag == classApplication|constructed|19 {
				continue // a referral to another domain: not followed
			}
			if err := resultError(op, classApplication|constructed|5); err != nil {
				return err
			}
			cookie = pagingCookie(controls)
			break
		}
		if cookie == "" {
			return nil
		}
	}
}

func parseEntry(op elem) (Entry, error) {
	parts, err := op.children()
	if err != nil || len(parts) < 2 {
		return Entry{}, errBER
	}
	e := Entry{DN: parts[0].str(), Attrs: map[string][]string{}}
	attrs, err := parts[1].children()
	if err != nil {
		return Entry{}, err
	}
	for _, a := range attrs {
		kv, err := a.children()
		if err != nil || len(kv) < 2 {
			return Entry{}, errBER
		}
		vals, err := kv[1].children()
		if err != nil {
			return Entry{}, err
		}
		name := strings.ToLower(kv[0].str())
		for _, v := range vals {
			e.Attrs[name] = append(e.Attrs[name], v.str())
		}
	}
	return e, nil
}

// pagingCookie is the cookie of the paging control among controls: "" when the list is done.
func pagingCookie(controls []elem) string {
	for _, c := range controls {
		parts, err := c.children()
		if err != nil || len(parts) < 2 || parts[0].str() != oidPaging {
			continue
		}
		v, _, err := decode(parts[len(parts)-1].val)
		if err != nil {
			return ""
		}
		if sc, err := v.children(); err == nil && len(sc) == 2 {
			return sc[1].str()
		}
	}
	return ""
}
