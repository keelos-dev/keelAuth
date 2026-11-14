// Package phone is the server side of logging in with the phone (keelApp; keelAuth docs/04):
// a phone is enrolled once with a one-time QR code and keeps a P-256 key in its secure
// store; a login page shows a QR code with a random challenge, the phone signs it, the page
// polls and gets the session. The password keeps working beside it.
//
// Enrolment: the page gets a code (NewEnrolment) and shows keelauth://enroll?o=<origin>&c=<code>;
// the phone makes a key pair and posts {code, name, platform, key, sig} to <origin>/phone/enroll,
// sig = ECDSA-P256-SHA256 over "keelauth-enroll\n" + origin + "\n" + code.
// Login: the page gets a challenge (NewChallenge) and shows keelauth://login?o=<origin>&c=<id>&n=<nonce>;
// the phone posts {c, n, device, sig} to <origin>/phone/approve, sig over
// "keelauth-login\n" + origin + "\n" + id + "\n" + nonce; the page polls with the id and its
// own poll key (never in the QR code) and gets the user when approved (Take).
// Keys: base64url of the 65-byte uncompressed point (0x04 X Y); signatures: base64url of
// r||s (64 bytes) or of the ASN.1 DER form.
package phone

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"net/url"
	"sync"
	"time"
)

// Device is an enrolled phone.
type Device struct {
	ID       string `json:"id"`
	User     string `json:"user"`
	Name     string `json:"name"`
	Platform string `json:"platform,omitempty"` // ios, android, …
	Key      string `json:"key"`                // base64url, 65 bytes uncompressed P-256
	Created  string `json:"created"`
	LastUsed string `json:"last_used,omitempty"`
}

// Store keeps the devices (keelauthd's state).
type Store interface {
	Devices() []Device
	Add(d Device) error
	Remove(id string) error
	Touch(id, when string) error
}

const (
	EnrolTTL     = 10 * time.Minute
	ChallengeTTL = 3 * time.Minute
	maxPending   = 1000
)

// Enrolment is a one-time code waiting for a phone.
type Enrolment struct {
	ID      string    `json:"id"`
	User    string    `json:"user"`
	URL     string    `json:"url"` // what the QR code says
	Expires time.Time `json:"expires"`
	code    string
	device  *Device // set once a phone enrolled
}

// Challenge is a login waiting for a phone.
type Challenge struct {
	ID      string    `json:"id"`
	Nonce   string    `json:"nonce"`
	Poll    string    `json:"poll"` // the page's own key for polling (not in the QR code)
	URL     string    `json:"url"`
	Expires time.Time `json:"expires"`
	user    string    // set when approved
	device  string
}

// Service holds the pending enrolments and challenges.
type Service struct {
	Store   Store
	Origin  func() string          // where phones reach keelauthd (https://host:port)
	Enabled func(user string) bool // the user may log in (exists, enabled)
	Now     func() time.Time
	mu      sync.Mutex
	enrols  map[string]*Enrolment // by id
	chals   map[string]*Challenge // by id
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) sweep(now time.Time) {
	if s.enrols == nil {
		s.enrols = map[string]*Enrolment{}
		s.chals = map[string]*Challenge{}
	}
	for id, e := range s.enrols {
		if now.After(e.Expires) || len(s.enrols) > maxPending {
			delete(s.enrols, id)
		}
	}
	for id, c := range s.chals {
		if now.After(c.Expires) || len(s.chals) > maxPending {
			delete(s.chals, id)
		}
	}
}

// NewEnrolment starts enrolling a phone for the user.
func (s *Service) NewEnrolment(user string) *Enrolment {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)
	e := &Enrolment{ID: random(16), User: user, Expires: now.Add(EnrolTTL), code: random(32)}
	e.URL = "keelauth://enroll?" + url.Values{"o": {s.Origin()}, "c": {e.code}}.Encode()
	s.enrols[e.ID] = e
	return e
}

// EnrolmentState: "pending", "done" (with the device) or "expired".
func (s *Service) EnrolmentState(id string) (string, *Device) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	e := s.enrols[id]
	switch {
	case e == nil:
		return "expired", nil
	case e.device != nil:
		d := *e.device
		delete(s.enrols, id)
		return "done", &d
	}
	return "pending", nil
}

// Enrol is the phone's call: the code, the phone's name, its key and its signature over the
// code. The device is stored; its user is returned.
func (s *Service) Enrol(code, name, platform, key, sig string) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)
	var e *Enrolment
	for _, x := range s.enrols {
		if x.code == code && x.device == nil {
			e = x
		}
	}
	if e == nil || code == "" {
		return nil, errors.New("unknown or used enrolment code")
	}
	pub, err := parseKey(key)
	if err != nil {
		return nil, err
	}
	if !verify(pub, "keelauth-enroll\n"+s.Origin()+"\n"+code, sig) {
		return nil, errors.New("bad signature")
	}
	if name == "" {
		name = "phone"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	d := Device{ID: random(12), User: e.User, Name: name, Platform: platform, Key: key, Created: now.UTC().Format(time.RFC3339)}
	if err := s.Store.Add(d); err != nil {
		return nil, err
	}
	e.device = &d
	return &d, nil
}

// NewChallenge starts a login.
func (s *Service) NewChallenge() *Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)
	c := &Challenge{ID: random(16), Nonce: random(32), Poll: random(16), Expires: now.Add(ChallengeTTL)}
	c.URL = "keelauth://login?" + url.Values{"o": {s.Origin()}, "c": {c.ID}, "n": {c.Nonce}}.Encode()
	s.chals[c.ID] = c
	return c
}

// Approve is the phone's call: the challenge, its nonce, the device and the signature.
func (s *Service) Approve(id, nonce, device, sig string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweep(now)
	c := s.chals[id]
	if c == nil || c.Nonce != nonce || nonce == "" {
		return errors.New("unknown or expired challenge")
	}
	if c.user != "" {
		return errors.New("already approved")
	}
	var d *Device
	for _, x := range s.Store.Devices() {
		if x.ID == device {
			d = &x
			break
		}
	}
	if d == nil {
		return errors.New("unknown device")
	}
	pub, err := parseKey(d.Key)
	if err != nil {
		return err
	}
	if !verify(pub, "keelauth-login\n"+s.Origin()+"\n"+id+"\n"+nonce, sig) {
		return errors.New("bad signature")
	}
	if s.Enabled != nil && !s.Enabled(d.User) {
		return errors.New("account disabled")
	}
	c.user, c.device = d.User, d.ID
	s.Store.Touch(d.ID, now.UTC().Format(time.RFC3339))
	return nil
}

// Nonce is a pending challenge's nonce (tests; the phone reads it from the QR code).
func (s *Service) Nonce(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c := s.chals[id]; c != nil {
		return c.Nonce
	}
	return ""
}

// Take is the page's poll: "pending", "expired", or "approved" with the user (once; the
// challenge is gone then). The poll key must match (the id alone is in the QR code).
func (s *Service) Take(id, poll string) (state, user, device string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweep(s.now())
	c := s.chals[id]
	if c == nil || c.Poll != poll || poll == "" {
		return "expired", "", ""
	}
	if c.user == "" {
		return "pending", "", ""
	}
	delete(s.chals, id)
	return "approved", c.user, c.device
}

// ---- keys ----

func parseKey(key string) (*ecdsa.PublicKey, error) {
	b, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(key)
	}
	if err != nil || len(b) != 65 || b[0] != 4 {
		return nil, errors.New("key: 65 bytes uncompressed P-256 point, base64url")
	}
	x, y := new(big.Int).SetBytes(b[1:33]), new(big.Int).SetBytes(b[33:])
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, errors.New("key: not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

func verify(pub *ecdsa.PublicKey, msg, sig string) bool {
	b, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(sig)
	}
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(msg))
	if len(b) == 64 {
		return ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:]))
	}
	return ecdsa.VerifyASN1(pub, h[:], b)
}

// EncodeKey is the wire form of a public key (tests, the app's reference).
func EncodeKey(pub *ecdsa.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(elliptic.Marshal(elliptic.P256(), pub.X, pub.Y))
}

// Sign makes a signature as the phone does (tests, the app's reference): r||s base64url.
func Sign(priv *ecdsa.PrivateKey, msg string) string {
	h := sha256.Sum256([]byte(msg))
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return ""
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return base64.RawURLEncoding.EncodeToString(out)
}
