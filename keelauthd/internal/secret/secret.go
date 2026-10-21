// Package secret holds keelauthd's small cryptography: the NT hash of a password (MD4 of its
// UTF-16LE form, what SMB and MSCHAPv2 check against) and the box that keeps secrets
// encrypted at rest in state.json (AES-256-GCM under the master key on the data disk).
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/bits"
	"strings"
	"unicode/utf16"
)

// NTHash is the NT hash of a password as 32 lower-case hex characters.
func NTHash(password string) string {
	u := utf16.Encode([]rune(password))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := MD4(b)
	return hex.EncodeToString(sum[:])
}

// MD4 is RFC 1320's digest. Only for the NT hash: MD4 is broken as a general hash, but the NT
// hash is defined with it and nothing else will do for SMB and MSCHAPv2.
func MD4(msg []byte) [16]byte {
	a, b, c, d := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	n := len(msg)
	pad := make([]byte, 0, n+72)
	pad = append(pad, msg...)
	pad = append(pad, 0x80)
	for len(pad)%64 != 56 {
		pad = append(pad, 0)
	}
	pad = binary.LittleEndian.AppendUint64(pad, uint64(n)*8)
	var x [16]uint32
	f := func(x, y, z uint32) uint32 { return x&y | ^x&z }
	g := func(x, y, z uint32) uint32 { return x&y | x&z | y&z }
	h := func(x, y, z uint32) uint32 { return x ^ y ^ z }
	for off := 0; off < len(pad); off += 64 {
		for i := range x {
			x[i] = binary.LittleEndian.Uint32(pad[off+4*i:])
		}
		aa, bb, cc, dd := a, b, c, d
		r1 := [4]int{3, 7, 11, 19}
		for i := 0; i < 16; i++ {
			s := r1[i%4]
			switch i % 4 {
			case 0:
				a = bits.RotateLeft32(a+f(b, c, d)+x[i], s)
			case 1:
				d = bits.RotateLeft32(d+f(a, b, c)+x[i], s)
			case 2:
				c = bits.RotateLeft32(c+f(d, a, b)+x[i], s)
			case 3:
				b = bits.RotateLeft32(b+f(c, d, a)+x[i], s)
			}
		}
		r2 := [4]int{3, 5, 9, 13}
		o2 := [16]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i := 0; i < 16; i++ {
			k, s := o2[i], r2[i%4]
			switch i % 4 {
			case 0:
				a = bits.RotateLeft32(a+g(b, c, d)+x[k]+0x5a827999, s)
			case 1:
				d = bits.RotateLeft32(d+g(a, b, c)+x[k]+0x5a827999, s)
			case 2:
				c = bits.RotateLeft32(c+g(d, a, b)+x[k]+0x5a827999, s)
			case 3:
				b = bits.RotateLeft32(b+g(c, d, a)+x[k]+0x5a827999, s)
			}
		}
		r3 := [4]int{3, 9, 11, 15}
		o3 := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i := 0; i < 16; i++ {
			k, s := o3[i], r3[i%4]
			switch i % 4 {
			case 0:
				a = bits.RotateLeft32(a+h(b, c, d)+x[k]+0x6ed9eba1, s)
			case 1:
				d = bits.RotateLeft32(d+h(a, b, c)+x[k]+0x6ed9eba1, s)
			case 2:
				c = bits.RotateLeft32(c+h(d, a, b)+x[k]+0x6ed9eba1, s)
			case 3:
				b = bits.RotateLeft32(b+h(c, d, a)+x[k]+0x6ed9eba1, s)
			}
		}
		a, b, c, d = a+aa, b+bb, c+cc, d+dd
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:], a)
	binary.LittleEndian.PutUint32(out[4:], b)
	binary.LittleEndian.PutUint32(out[8:], c)
	binary.LittleEndian.PutUint32(out[12:], d)
	return out
}

// Box seals and opens secrets with a 32-byte key. A sealed value is "v1:" + base64(nonce|ciphertext).
type Box struct{ aead cipher.AEAD }

// NewBox makes a box from a 32-byte key.
func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("the master key must be 32 bytes")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &Box{a}, nil
}

const prefix = "v1:"

// Seal encrypts s; "" stays "".
func (b *Box) Seal(s string) string {
	if s == "" {
		return ""
	}
	nonce := make([]byte, b.aead.NonceSize())
	rand.Read(nonce)
	out := b.aead.Seal(nonce, nonce, []byte(s), nil)
	return prefix + base64.StdEncoding.EncodeToString(out)
}

// Open decrypts a value made by Seal; "" stays "".
func (b *Box) Open(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	raw, ok := strings.CutPrefix(v, prefix)
	if !ok {
		return "", errors.New("not a sealed value")
	}
	ct, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return "", err
	}
	ns := b.aead.NonceSize()
	if len(ct) < ns {
		return "", errors.New("sealed value too short")
	}
	pt, err := b.aead.Open(nil, ct[:ns], ct[ns:], nil)
	if err != nil {
		return "", errors.New("cannot decrypt (another master key?)")
	}
	return string(pt), nil
}

// Random is n random bytes as lower-case hex.
func Random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Password makes a password people can type: groups of letters and digits joined by "-",
// without look-alikes (0/o, 1/l/i). 4 groups of 4: about 80 bits, and it passes Kanidm's
// quality check.
func Password() string {
	const al = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	var sb strings.Builder
	for i, c := range b {
		if i > 0 && i%4 == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(al[int(c)%len(al)])
	}
	return sb.String()
}
