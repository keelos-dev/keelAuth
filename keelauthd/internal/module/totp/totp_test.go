package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B vectors (SHA-1, the 20-byte secret "12345678901234567890"), 8 digits
// there; we compare the last 6.
func TestVectors(t *testing.T) {
	secret := enc.EncodeToString([]byte("12345678901234567890"))
	for _, tc := range []struct {
		at   int64
		code string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, err := Code(secret, Step(time.Unix(tc.at, 0)))
		if err != nil || got != tc.code[2:] {
			t.Errorf("at %d: %s, want %s (%v)", tc.at, got, tc.code[2:], err)
		}
	}
}

func TestVerify(t *testing.T) {
	s := NewSecret()
	if len(s) != 32 {
		t.Fatalf("secret %q", s)
	}
	now := time.Unix(1700000000, 0)
	code, _ := Code(s, Step(now))
	if ok, step := Verify(s, code, now); !ok || step != Step(now) {
		t.Fatal("own code refused")
	}
	if ok, _ := Verify(s, code, now.Add(31*time.Second)); !ok {
		t.Fatal("previous step refused")
	}
	if ok, _ := Verify(s, code, now.Add(61*time.Second)); ok {
		t.Fatal("two steps back accepted")
	}
	if ok, _ := Verify(s, "000000", now); ok && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	if ok, _ := Verify(s, "12345", now); ok {
		t.Fatal("short code accepted")
	}
	u := URL("keelAuth", "anna", s)
	if !strings.HasPrefix(u, "otpauth://totp/keelAuth:anna?") || !strings.Contains(u, "secret="+s) || !strings.Contains(u, "issuer=keelAuth") {
		t.Fatalf("url %s", u)
	}
	if _, err := Code("not base32!", 1); err == nil {
		t.Fatal("bad secret accepted")
	}
}
