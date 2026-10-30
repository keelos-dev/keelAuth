// Package ldap is keelAuth's own read-only LDAP server (docs/01 "2026-10-30 晚", module
// ldap): LDAPv3 over TLS, simple binds (a person with the password, a device with its token,
// keelAuth's shared bind account), searches over the people and groups of the account store,
// answered the way Kanidm answered them (same DNs, attribute names and object classes), so
// every client configured for keelAuth keeps working. Nothing is written through it.
//
// This file: the little of BER (ITU-T X.690) LDAP needs.
package ldap

import (
	"errors"
	"fmt"
)

// BER tag classes and the tags LDAP uses.
const (
	classUniversal   = 0x00
	classApplication = 0x40
	classContext     = 0x80
	constructed      = 0x20

	tagBoolean     = 0x01
	tagInteger     = 0x02
	tagOctetString = 0x04
	tagEnumerated  = 0x0a
	tagSequence    = 0x30 // 0x10 | constructed
	tagSet         = 0x31
)

var errBER = errors.New("malformed BER")

// elem is one decoded BER element: its tag byte (class, constructed bit and number for the
// small numbers LDAP uses) and content bytes.
type elem struct {
	tag byte
	val []byte
}

// decode reads one element from b; rest is what follows it.
func decode(b []byte) (e elem, rest []byte, err error) {
	if len(b) < 2 {
		return e, nil, errBER
	}
	e.tag = b[0]
	if e.tag&0x1f == 0x1f { // multi-byte tag numbers: not used by LDAP
		return e, nil, fmt.Errorf("%w: long tag", errBER)
	}
	n, i := int(b[1]), 2
	if n&0x80 != 0 {
		k := n & 0x7f
		if k == 0 || k > 4 || len(b) < 2+k {
			return e, nil, fmt.Errorf("%w: length", errBER)
		}
		n = 0
		for j := 0; j < k; j++ {
			n = n<<8 | int(b[2+j])
		}
		i = 2 + k
	}
	if n < 0 || len(b) < i+n {
		return e, nil, fmt.Errorf("%w: short", errBER)
	}
	e.val = b[i : i+n]
	return e, b[i+n:], nil
}

// children decodes a constructed element's content.
func (e elem) children() ([]elem, error) {
	var out []elem
	b := e.val
	for len(b) > 0 {
		c, rest, err := decode(b)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		b = rest
	}
	return out, nil
}

func (e elem) int() (int, error) {
	if len(e.val) == 0 || len(e.val) > 8 {
		return 0, fmt.Errorf("%w: integer", errBER)
	}
	n := 0
	if e.val[0]&0x80 != 0 {
		n = -1
	}
	for _, c := range e.val {
		n = n<<8 | int(c)
	}
	return n, nil
}

func (e elem) str() string { return string(e.val) }

func (e elem) bool() bool { return len(e.val) > 0 && e.val[0] != 0 }

// ---- encoding ----

func encLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for x := n; x > 0; x >>= 8 {
		b = append([]byte{byte(x)}, b...)
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// enc is one element: tag, length, content.
func enc(tag byte, val []byte) []byte {
	out := []byte{tag}
	out = append(out, encLen(len(val))...)
	return append(out, val...)
}

func encInt(tag byte, n int) []byte {
	var b []byte
	for {
		b = append([]byte{byte(n)}, b...)
		if n >= -128 && n < 128 {
			break
		}
		n >>= 8
	}
	// a positive number must not look negative
	if n >= 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return enc(tag, b)
}

func encStr(s string) []byte        { return enc(tagOctetString, []byte(s)) }
func encSeq(parts ...[]byte) []byte { return enc(tagSequence, join(parts...)) }
func encSet(parts ...[]byte) []byte { return enc(tagSet, join(parts...)) }
func encBool(v bool) []byte {
	b := byte(0)
	if v {
		b = 0xff
	}
	return enc(tagBoolean, []byte{b})
}
func encEnum(n int) []byte { return encInt(tagEnumerated, n) }
func encApp(n byte, parts ...[]byte) []byte {
	return enc(classApplication|constructed|n, join(parts...))
}

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
