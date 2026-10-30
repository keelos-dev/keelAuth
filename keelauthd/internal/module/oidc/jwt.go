// Package oidc is keelAuth's own OpenID Connect provider (docs/01 "2026-10-30 晚", module
// oidc): the authorization code flow with PKCE, ID tokens signed with ES256 (RS256 for a
// client that asks), userinfo, JWKS, introspection, a login page of its own, and the
// applications page. The URLs are the ones Kanidm served (issuer <origin>/oauth2/openid/<client>,
// /ui/oauth2, /oauth2/token, /ui/login), so keelOS and every application configured
// for keelAuth keep working.
//
// This file: the signing keys and the little of JOSE needed.
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
)

// keyStore keeps one signing key per client (and algorithm) in a JSON file (0600).
type keyStore struct {
	mu   sync.Mutex
	path string // "" = memory
	keys map[string]*storedKey
}

type storedKey struct {
	Alg string `json:"alg"` // ES256 or RS256
	PEM string `json:"pem"` // PKCS#8
	Kid string `json:"kid"`
}

func newKeyStore(dir string) (*keyStore, error) {
	ks := &keyStore{keys: map[string]*storedKey{}}
	if dir == "" {
		return ks, nil
	}
	ks.path = filepath.Join(dir, "oidc-keys.json")
	b, err := os.ReadFile(ks.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		if err := json.Unmarshal(b, &ks.keys); err != nil {
			return nil, err
		}
	}
	return ks, nil
}

func (ks *keyStore) save() error {
	if ks.path == "" {
		return nil
	}
	b, _ := json.MarshalIndent(ks.keys, "", "  ")
	tmp := ks.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ks.path)
}

// signer is a client's key, ready to sign.
type signer struct {
	alg string
	kid string
	key crypto.Signer
}

// get is the client's key for the algorithm, made at the first use.
func (ks *keyStore) get(client, alg string) (*signer, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	id := client + ":" + alg
	sk := ks.keys[id]
	if sk == nil {
		var key crypto.Signer
		var err error
		if alg == "RS256" {
			key, err = rsa.GenerateKey(rand.Reader, 2048)
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, err
		}
		pub, _ := x509.MarshalPKIXPublicKey(key.Public())
		sum := sha256.Sum256(pub)
		sk = &storedKey{Alg: alg, PEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), Kid: hex.EncodeToString(sum[:8])}
		ks.keys[id] = sk
		if err := ks.save(); err != nil {
			delete(ks.keys, id)
			return nil, err
		}
	}
	blk, _ := pem.Decode([]byte(sk.PEM))
	if blk == nil {
		return nil, errors.New("key: bad PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	return &signer{alg: sk.Alg, kid: sk.Kid, key: k.(crypto.Signer)}, nil
}

// drop forgets a client's keys (the client was deleted).
func (ks *keyStore) drop(client string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, alg := range []string{"ES256", "RS256"} {
		delete(ks.keys, client+":"+alg)
	}
	ks.save()
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// jwk is the key's public half for the JWKS.
func (s *signer) jwk() map[string]any {
	switch k := s.key.Public().(type) {
	case *ecdsa.PublicKey:
		return map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": s.kid,
			"x": b64u(k.X.FillBytes(make([]byte, 32))), "y": b64u(k.Y.FillBytes(make([]byte, 32)))}
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": s.kid,
			"n": b64u(k.N.Bytes()), "e": b64u(big.NewInt(int64(k.E)).Bytes())}
	}
	return nil
}

// sign makes a JWT (compact serialization) of the claims.
func (s *signer) sign(claims map[string]any) (string, error) {
	hdr, _ := json.Marshal(map[string]string{"alg": s.alg, "kid": s.kid, "typ": "JWT"})
	body, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := b64u(hdr) + "." + b64u(body)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := s.key.(type) {
	case *ecdsa.PrivateKey:
		r, sN, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			return "", err
		}
		sig = append(r.FillBytes(make([]byte, 32)), sN.FillBytes(make([]byte, 32))...)
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		if err != nil {
			return "", err
		}
	default:
		return "", errors.New("key: unknown type")
	}
	return signed + "." + b64u(sig), nil
}

// random is n random bytes, base64url (tokens, codes, session ids).
func random(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64u(b)
}
