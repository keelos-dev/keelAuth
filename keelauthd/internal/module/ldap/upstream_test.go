package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// fakeAD answers like a directory: StartTLS (when plain), bind (ad\reader / pw), and a paged
// search that gives n people, at most 500 an answer whatever the client asks.
type fakeAD struct {
	n         int
	pages     int
	plainBind bool // a bind arrived before TLS
}

func testCert(t *testing.T) tls.Certificate {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dc1"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *fakeAD) serve(t *testing.T, startTLS bool) string {
	cert := testCert(t)
	conf := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if !startTLS {
					c = tls.Server(c, conf)
				}
				f.conn(c, conf, !startTLS)
			}()
		}
	}()
	return ln.Addr().String()
}

func (f *fakeAD) conn(c net.Conn, conf *tls.Config, secure bool) {
	reply := func(id int, op []byte, controls []byte) {
		msg := join(encInt(tagInteger, id), op)
		if controls != nil {
			msg = append(msg, enc(classContext|constructed|0, controls)...)
		}
		c.Write(encSeq(msg))
	}
	result := func(code int, text string) []byte { return join(encEnum(code), encStr(""), encStr(text)) }
	for {
		m, err := readMessage(c)
		if err != nil {
			return
		}
		parts, _ := m.children()
		id, _ := parts[0].int()
		op := parts[1]
		switch op.tag {
		case classApplication | constructed | 23: // extended: StartTLS
			reply(id, enc(classApplication|constructed|24, result(0, "")), nil)
			tc := tls.Server(c, conf)
			c, secure = tc, true
		case classApplication | constructed | 0: // bind
			if !secure {
				f.plainBind = true
			}
			b, _ := op.children()
			code := 49
			if b[1].str() == `ad\reader` && b[2].str() == "pw" {
				code = 0
			}
			reply(id, enc(classApplication|constructed|1, result(code, "80090308: LdapErr: DSID-0C09044E, data 52e\x00")), nil)
		case classApplication | constructed | 3: // search
			start := 0
			if len(parts) > 2 {
				ctl, _ := parts[2].children()
				cp, _ := ctl[0].children()
				v, _, _ := decode(cp[len(cp)-1].val)
				sc, _ := v.children()
				fmt.Sscanf(sc[1].str(), "%d", &start)
			}
			f.pages++
			end := start + 500
			if end > f.n {
				end = f.n
			}
			for i := start; i < end; i++ {
				attrs := encSeq(
					encSeq(encStr("sAMAccountName"), encSet(encStr(fmt.Sprintf("user%04d", i)))),
					encSeq(encStr("memberOf"), encSet(encStr("CN=営業,DC=ad,DC=example"), encStr("CN=All,DC=ad,DC=example"))))
				reply(id, encApp(4, encStr(fmt.Sprintf("CN=田中 %d,DC=ad,DC=example", i)), attrs), nil)
			}
			reply(id, encApp(19, encStr("ldap://other.example/DC=other")), nil) // a referral: ignored
			cookie := ""
			if end < f.n {
				cookie = fmt.Sprint(end)
			}
			ctl := encSeq(encStr(oidPaging), encStr(string(encSeq(encInt(tagInteger, 0), encStr(cookie)))))
			reply(id, encApp(5, result(0, "")), ctl)
		}
	}
}

func TestUpstream(t *testing.T) {
	for _, startTLS := range []bool{false, true} {
		t.Run(fmt.Sprintf("starttls=%v", startTLS), func(t *testing.T) {
			f := &fakeAD{n: 1234}
			addr := f.serve(t, startTLS)
			host, port, _ := net.SplitHostPort(addr)
			dial := func(pin string) (*Upstream, error) {
				u, err := dialOne(context.Background(), host, port, startTLS)
				if err != nil {
					return nil, err
				}
				if normFingerprint(pin) != u.Fingerprint {
					u.Close()
					return nil, &PinError{Got: u.Fingerprint}
				}
				return u, nil
			}
			_, err := dial("")
			var pe *PinError
			if !errors.As(err, &pe) || len(pe.Got) != 64 {
				t.Fatalf("no accepted fingerprint: %v", err)
			}
			u, err := dial(pe.Got[:32] + ":" + pe.Got[32:])
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			if err := u.Bind(`ad\reader`, "wrong"); !errors.Is(err, ErrUpstreamLogin) {
				t.Fatalf("wrong password: %v", err)
			}
			if err := u.Bind(`ad\reader`, ""); !errors.Is(err, ErrUpstreamLogin) {
				t.Fatalf("empty password: %v", err)
			}
			if err := u.Bind(`ad\reader`, "pw"); err != nil {
				t.Fatal(err)
			}
			var got []Entry
			err = u.Search("DC=ad,DC=example", false, And(Eq("objectCategory", "person"), Present("sAMAccountName")),
				[]string{"sAMAccountName", "memberOf"}, func(e Entry) error { got = append(got, e); return nil })
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1234 || f.pages != 3 {
				t.Fatalf("%d entries in %d pages", len(got), f.pages)
			}
			last := got[1233]
			if last.DN != "CN=田中 1233,DC=ad,DC=example" || last.First("samaccountname") != "user1233" || len(last.Attrs["memberof"]) != 2 || last.Attrs["memberof"][0] != "CN=営業,DC=ad,DC=example" {
				t.Fatalf("last entry: %+v", last)
			}
			if f.plainBind {
				t.Fatal("a password crossed the connection before TLS")
			}
		})
	}
}

func TestDialUpstreamPort(t *testing.T) {
	f := &fakeAD{}
	addr := f.serve(t, false)
	_, err := DialUpstream(context.Background(), addr, "")
	var pe *PinError
	if !errors.As(err, &pe) {
		t.Fatalf("want the fingerprint, got %v", err)
	}
	u, err := DialUpstream(context.Background(), addr, pe.Got)
	if err != nil {
		t.Fatal(err)
	}
	u.Close()
	if _, err := DialUpstream(context.Background(), "127.0.0.1:1", ""); err == nil || errors.As(err, &pe) {
		t.Fatalf("closed port: %v", err)
	}
}
