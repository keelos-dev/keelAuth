package secret

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestMD4(t *testing.T) {
	// RFC 1320 appendix A.5
	for in, want := range map[string]string{
		"":                           "31d6cfe0d16ae931b73c59d7e0c089c0",
		"a":                          "bde52cb31de33e46245e05fbdbd6fb24",
		"abc":                        "a448017aaf21d8525fc10ae87aa6729d",
		"message digest":             "d9130a8164549fe818874806e1c7014b",
		"abcdefghijklmnopqrstuvwxyz": "d79e1c308aa5bbcdeea8ed63df412da9",
		"12345678901234567890123456789012345678901234567890123456789012345678901234567890": "e33b4ddc9c38f2199c3e7b164fcc0536",
	} {
		got := MD4([]byte(in))
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("MD4(%q) = %x, want %s", in, got, want)
		}
	}
}

func TestNTHash(t *testing.T) {
	for in, want := range map[string]string{
		"password":       "8846f7eaee8fb117ad06bdd830b7586c",
		"":               "31d6cfe0d16ae931b73c59d7e0c089c0",
		"Keel-Auth-2026": NTHash("Keel-Auth-2026"), // stable
	} {
		if got := NTHash(in); got != want {
			t.Errorf("NTHash(%q) = %s, want %s", in, got, want)
		}
	}
	// non-ASCII goes through UTF-16LE: "ü" is 0xFC 0x00
	if NTHash("ü") != hex.EncodeToString(func() []byte { s := MD4([]byte{0xfc, 0}); return s[:] }()) {
		t.Error("non-ASCII password not hashed as UTF-16LE")
	}
}

func TestBox(t *testing.T) {
	k := make([]byte, 32)
	b, err := NewBox(k)
	if err != nil {
		t.Fatal(err)
	}
	s := b.Seal("hello")
	if !strings.HasPrefix(s, "v1:") || strings.Contains(s, "hello") {
		t.Fatalf("sealed %q", s)
	}
	if s == b.Seal("hello") {
		t.Error("two seals are equal: nonce reused")
	}
	got, err := b.Open(s)
	if err != nil || got != "hello" {
		t.Fatalf("open = %q, %v", got, err)
	}
	if v, _ := b.Open(""); v != "" || b.Seal("") != "" {
		t.Error("empty must stay empty")
	}
	k2 := make([]byte, 32)
	k2[0] = 1
	b2, _ := NewBox(k2)
	if _, err := b2.Open(s); err == nil {
		t.Error("opened with another key")
	}
	if _, err := NewBox(k[:16]); err == nil {
		t.Error("short key accepted")
	}
}

func TestPassword(t *testing.T) {
	p := Password()
	if len(p) != 19 || strings.Count(p, "-") != 3 {
		t.Errorf("password %q", p)
	}
	if p == Password() {
		t.Error("same password twice")
	}
}
