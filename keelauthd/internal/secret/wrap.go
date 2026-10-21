package secret

import (
	"crypto/hkdf"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"strings"
)

// Key-encryption keys (KEKs) for the master key (docs/02 §2.1). The master key never lies in
// clear on the data disk or in a backup: it is sealed under a KEK, and the KEK is
//   - keel's: HKDF-SHA256 of the instance key on keel's seed disk (keel computes the same and
//     hands it out as the "recovery key", keelOS keel/internal/web/auth.go authRecoveryKey);
//   - a passphrase's: PBKDF2-SHA256 of the recovery passphrase of a standalone keelAuth.

// KEKInfo is HKDF's info for keel's KEK. keel uses the same string: never change it.
const KEKInfo = "keelauth master key wrap v1"

// RecoveryPrefix starts a recovery key.
const RecoveryPrefix = "KAR1"

// PassIter is PBKDF2's iteration count for a new passphrase slot (OWASP 2023 for SHA-256).
var PassIter = 600000

// KeelKEK is the KEK derived from an instance key (64 hex characters).
func KeelKEK(instanceKeyHex string) ([]byte, error) {
	k, err := hex.DecodeString(instanceKeyHex)
	if err != nil || len(k) != 32 {
		return nil, errors.New("the instance key must be 64 hex characters")
	}
	return hkdf.Key(sha256.New, k, nil, KEKInfo, 32)
}

// PassKEK is the KEK of a passphrase.
func PassKEK(pass string, salt []byte, iter int) ([]byte, error) {
	return pbkdf2.Key(sha256.New, pass, salt, iter, 32)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// RecoveryKey writes a KEK for people: "KAR1-" and the KEK with a 2-byte check (the start of
// its SHA-256) in base32, in groups of five: KAR1-ABCDE-…-XYZ (11 groups).
func RecoveryKey(kek []byte) string {
	sum := sha256.Sum256(kek)
	s := b32.EncodeToString(append(append([]byte{}, kek...), sum[:2]...))
	var g []string
	for len(s) > 5 {
		g = append(g, s[:5])
		s = s[5:]
	}
	g = append(g, s)
	return RecoveryPrefix + "-" + strings.Join(g, "-")
}

// ParseRecoveryKey reads a recovery key back into its KEK. Case, spaces and dashes do not
// matter; a typo is caught by the check bytes.
func ParseRecoveryKey(s string) ([]byte, error) {
	s = strings.ToUpper(strings.Join(strings.FieldsFunc(s, func(r rune) bool { return r == '-' || r == ' ' || r == '\n' || r == '\t' || r == '\r' }), ""))
	rest, ok := strings.CutPrefix(s, RecoveryPrefix)
	if !ok {
		return nil, errors.New("not a recovery key (it starts with " + RecoveryPrefix + "-)")
	}
	b, err := b32.DecodeString(rest)
	if err != nil || len(b) != 34 {
		return nil, errors.New("the recovery key is mistyped (wrong length or letters)")
	}
	kek := b[:32]
	if sum := sha256.Sum256(kek); sum[0] != b[32] || sum[1] != b[33] {
		return nil, errors.New("the recovery key is mistyped (its check does not match)")
	}
	return kek, nil
}
