// Package totp is the second factor without keelApp (keelAuth docs/01 "二次认证"): a
// time-based one-time password (RFC 6238, SHA-1, 6 digits, 30 s) that any authenticator app
// enrols by scanning an otpauth:// QR code.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Period = 30
	Digits = 6
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret is a fresh 20-byte secret, base32 (what authenticator apps take).
func NewSecret() string {
	b := make([]byte, 20)
	rand.Read(b)
	return enc.EncodeToString(b)
}

// URL is what the QR code says: otpauth://totp/<issuer>:<account>?secret=…&issuer=…
func URL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Code is the code for the time step (the counter).
func Code(secret string, counter int64) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", fmt.Errorf("secret: not base32")
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	h := m.Sum(nil)
	off := h[len(h)-1] & 0x0f
	v := binary.BigEndian.Uint32(h[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", Digits, v%1000000), nil
}

// Step is the counter at a time.
func Step(t time.Time) int64 { return t.Unix() / Period }

// Verify checks a code against the steps now-1, now, now+1 (clock drift) and says which step
// matched, so the caller can refuse a replay (a step is used once).
func Verify(secret, code string, now time.Time) (ok bool, step int64) {
	code = strings.TrimSpace(code)
	if len(code) != Digits {
		return false, 0
	}
	cur := Step(now)
	for _, c := range []int64{cur, cur - 1, cur + 1} {
		want, err := Code(secret, c)
		if err != nil {
			return false, 0
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true, c
		}
	}
	return false, 0
}
