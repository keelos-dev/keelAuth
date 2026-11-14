package phone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"
)

type memStore struct{ ds []Device }

func (m *memStore) Devices() []Device  { return append([]Device{}, m.ds...) }
func (m *memStore) Add(d Device) error { m.ds = append(m.ds, d); return nil }
func (m *memStore) Remove(id string) error {
	for i, d := range m.ds {
		if d.ID == id {
			m.ds = append(m.ds[:i], m.ds[i+1:]...)
			return nil
		}
	}
	return errors.New("none")
}
func (m *memStore) Touch(id, when string) error {
	for i := range m.ds {
		if m.ds[i].ID == id {
			m.ds[i].LastUsed = when
		}
	}
	return nil
}

func TestEnrolAndLogin(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	st := &memStore{}
	enabled := map[string]bool{"alice": true}
	s := &Service{Store: st, Origin: func() string { return "https://192.0.2.10:8443" }, Enabled: func(u string) bool { return enabled[u] }, Now: func() time.Time { return now }}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key := EncodeKey(&priv.PublicKey)

	e := s.NewEnrolment("alice")
	u, _ := url.Parse(e.URL)
	if u.Scheme != "keelauth" || u.Host != "enroll" || u.Query().Get("o") != "https://192.0.2.10:8443" || u.Query().Get("c") == "" {
		t.Fatalf("enrol url %s", e.URL)
	}
	if st, _ := s.EnrolmentState(e.ID); st != "pending" {
		t.Fatal(st)
	}
	code := u.Query().Get("c")
	if _, err := s.Enrol(code, "Alice's phone", "ios", key, Sign(priv, "keelauth-enroll\nhttps://192.0.2.10:8443\nwrong")); err == nil {
		t.Fatal("bad signature accepted")
	}
	d, err := s.Enrol(code, "Alice's phone", "ios", key, Sign(priv, "keelauth-enroll\nhttps://192.0.2.10:8443\n"+code))
	if err != nil || d.User != "alice" || len(st.ds) != 1 {
		t.Fatalf("enrol: %v %+v", err, d)
	}
	if _, err := s.Enrol(code, "again", "ios", key, Sign(priv, "keelauth-enroll\nhttps://192.0.2.10:8443\n"+code)); err == nil {
		t.Fatal("code used twice")
	}
	if st, got := s.EnrolmentState(e.ID); st != "done" || got.ID != d.ID {
		t.Fatal(st)
	}
	if st, _ := s.EnrolmentState(e.ID); st != "expired" {
		t.Fatal("enrolment not gone after done")
	}

	c := s.NewChallenge()
	cu, _ := url.Parse(c.URL)
	if cu.Host != "login" || cu.Query().Get("c") != c.ID || cu.Query().Get("n") != c.Nonce {
		t.Fatalf("login url %s", c.URL)
	}
	if st, _, _ := s.Take(c.ID, c.Poll); st != "pending" {
		t.Fatal(st)
	}
	if st, _, _ := s.Take(c.ID, "wrong"); st != "expired" {
		t.Fatal("poll key not checked")
	}
	msg := "keelauth-login\nhttps://192.0.2.10:8443\n" + c.ID + "\n" + c.Nonce
	if err := s.Approve(c.ID, "x", d.ID, Sign(priv, msg)); err == nil {
		t.Fatal("wrong nonce accepted")
	}
	if err := s.Approve(c.ID, c.Nonce, "nodev", Sign(priv, msg)); err == nil {
		t.Fatal("unknown device accepted")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := s.Approve(c.ID, c.Nonce, d.ID, Sign(other, msg)); err == nil {
		t.Fatal("other key accepted")
	}
	enabled["alice"] = false
	if err := s.Approve(c.ID, c.Nonce, d.ID, Sign(priv, msg)); err == nil {
		t.Fatal("disabled user approved")
	}
	enabled["alice"] = true
	if err := s.Approve(c.ID, c.Nonce, d.ID, Sign(priv, msg)); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(c.ID, c.Nonce, d.ID, Sign(priv, msg)); err == nil {
		t.Fatal("approved twice")
	}
	if st, user, dev := s.Take(c.ID, c.Poll); st != "approved" || user != "alice" || dev != d.ID {
		t.Fatalf("take: %s %s %s", st, user, dev)
	}
	if st, _, _ := s.Take(c.ID, c.Poll); st != "expired" {
		t.Fatal("taken twice")
	}
	if st.ds[0].LastUsed == "" {
		t.Fatal("last_used not set")
	}
	// expiry
	c2 := s.NewChallenge()
	now = now.Add(ChallengeTTL + time.Second)
	if st, _, _ := s.Take(c2.ID, c2.Poll); st != "expired" {
		t.Fatal("not expired")
	}
	// DER signatures (Android) work too
	c3 := s.NewChallenge()
	h := msgHash("keelauth-login\nhttps://192.0.2.10:8443\n" + c3.ID + "\n" + c3.Nonce)
	der, _ := ecdsa.SignASN1(rand.Reader, priv, h)
	if err := s.Approve(c3.ID, c3.Nonce, d.ID, b64(der)); err != nil {
		t.Fatalf("der: %v", err)
	}
}

func msgHash(msg string) []byte { h := sha256.Sum256([]byte(msg)); return h[:] }
func b64(b []byte) string       { return base64.RawURLEncoding.EncodeToString(b) }
