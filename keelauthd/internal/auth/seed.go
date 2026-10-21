package auth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// The seed disk (docs/02 section 4, as keelNAS's docs/04 section 10.1): keelOS gives a new
// keelAuth a small extra disk whose first bytes are a JSON object, the rest zeros. It carries the
// key, the port to listen on and how to reach keel. keelauthd looks for it at every start.

const (
	SeedMagic = 1    // "keelauth_seed"
	SeedSize  = 4096 // bytes read from the start of each candidate disk
)

// Seed is the seed disk's content.
type Seed struct {
	Magic       int      `json:"keelauth_seed"`
	Key         string   `json:"key"`
	Port        int      `json:"port"`
	Keel        []string `json:"keel"`
	Fingerprint string   `json:"fingerprint"`
	// SPKI: the SHA-256 of keel's public key (the leaf's SubjectPublicKeyInfo), AB:CD:…. keel
	// re-issues its certificate with the same key when its name or address changes, so this
	// survives that; when the seed has it, it is what keel is checked against (fingerprint is
	// then not looked at). Seeds from keelOS before 2026-10-07 have none: the certificate's
	// fingerprint is pinned.
	SPKI string `json:"spki,omitempty"`
	// Internal: the NIC that connects only keelNAS and its host (network.go): its MAC and the
	// address keelNAS takes on it. Older seeds have none.
	Internal *SeedInternal `json:"internal,omitempty"`
	// Domain: Kanidm's domain, used only at the first start (no engine database yet).
	Domain string `json:"domain,omitempty"`
	// RegisterPath: where to register with keel; "" = DefaultRegisterPath.
	RegisterPath string `json:"register_path,omitempty"`
	// Timezone: keel's time zone when it made the seed (keelOS docs/47); keel's answers to the
	// registration carry the current one.
	Timezone string `json:"timezone,omitempty"`

	fp   []byte // Fingerprint as 32 bytes
	spki []byte // SPKI as 32 bytes, nil = none
}

// SeedInternal is the seed's "internal".
type SeedInternal struct {
	MAC     string `json:"mac"`
	Address string `json:"address"` // 169.254.77.2/24
}

// domainRE: a DNS name with at least two labels.
var domainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)

// ErrNotSeed: the bytes are not a seed at all (zeros, other data, no "keelauth_seed": 1).
// Any other error from ParseSeed is a seed that is broken.
var ErrNotSeed = errors.New("not a seed")

// ParseSeed reads a seed disk's first bytes: trailing NULs are stripped, the rest must be a
// JSON object with "keelauth_seed": 1 and valid fields.
func ParseSeed(b []byte) (*Seed, error) {
	b = bytes.TrimRight(b, "\x00")
	if len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{' {
		return nil, ErrNotSeed
	}
	var probe struct {
		Magic *int `json:"keelauth_seed"`
	}
	if json.Unmarshal(b, &probe) != nil || probe.Magic == nil {
		return nil, ErrNotSeed
	}
	if *probe.Magic != SeedMagic {
		return nil, fmt.Errorf("seed version %d is not supported", *probe.Magic)
	}
	var sd Seed
	if err := json.Unmarshal(b, &sd); err != nil {
		return nil, fmt.Errorf("seed: %v", err)
	}
	if len(sd.Key) != 64 {
		return nil, fmt.Errorf("seed: the key must be 64 hex characters, it has %d", len(sd.Key))
	}
	if _, err := hex.DecodeString(sd.Key); err != nil {
		return nil, fmt.Errorf("seed: the key is not hex")
	}
	if sd.Port < 1 || sd.Port > 65535 {
		return nil, fmt.Errorf("seed: bad port %d", sd.Port)
	}
	if len(sd.Keel) == 0 {
		return nil, fmt.Errorf("seed: no keel address")
	}
	for _, k := range sd.Keel {
		u, err := url.Parse(k)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("seed: keel address %q is not an https URL", k)
		}
	}
	if in := sd.Internal; in != nil {
		in.MAC = strings.ToLower(in.MAC)
		if !macRE.MatchString(in.MAC) {
			return nil, fmt.Errorf("seed: internal mac %q", in.MAC)
		}
		if ip, _, err := net.ParseCIDR(in.Address); err != nil || ip.To4() == nil {
			return nil, fmt.Errorf("seed: internal address %q", in.Address)
		}
	}
	if sd.Domain != "" && !domainRE.MatchString(sd.Domain) {
		return nil, fmt.Errorf("seed: domain %q", sd.Domain)
	}
	if sd.RegisterPath != "" && !strings.HasPrefix(sd.RegisterPath, "/") {
		return nil, fmt.Errorf("seed: register_path %q must start with /", sd.RegisterPath)
	}
	fp, err := ParseFingerprint(sd.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("seed: %v", err)
	}
	sd.fp = fp
	if sd.SPKI != "" {
		if sd.spki, err = ParseFingerprint(sd.SPKI); err != nil {
			return nil, fmt.Errorf("seed: spki: %v", err)
		}
	}
	return &sd, nil
}

// ParseFingerprint reads "AB:CD:…" (32 bytes of SHA-256; case and colons are not enforced).
func ParseFingerprint(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("fingerprint %q is not a SHA-256 in the form AB:CD:…", s)
	}
	return b, nil
}

// FormatFingerprint writes a SHA-256 as "AB:CD:…" (upper-case hex, colons).
func FormatFingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, c := range sum {
		parts[i] = fmt.Sprintf("%02X", c)
	}
	return strings.Join(parts, ":")
}

// SeedListen is the internal listener a seed asks for: the internal address when the seed has
// one (keel's link only), else every address; the seed's port.
func SeedListen(sd *Seed) string {
	if sd.Internal != nil {
		ip, _, _ := net.ParseCIDR(sd.Internal.Address)
		return net.JoinHostPort(ip.String(), fmt.Sprint(sd.Port))
	}
	return fmt.Sprintf(":%d", sd.Port)
}

// AdoptSeed takes the seed's listen address into st (and its domain while there is no engine
// database yet: fresh) and reports whether st changed. The key stays on the seed (the server
// reads it from there: linkKey), never in state.json.
func AdoptSeed(st *State, sd *Seed, fresh bool) bool {
	changed := false
	if l := SeedListen(sd); st.Listen != l {
		st.Listen = l
		changed = true
	}
	if fresh && sd.Domain != "" && st.Domain != sd.Domain {
		st.Domain = sd.Domain
		changed = true
	}
	return changed
}

// findSeed reads the first bytes of every disk (kern.disks, CD drives left out) and returns the
// first seed found and its disk. The system and data disks start with a partition table, so
// they are never mistaken for one.
func (s *Server) findSeed() (*Seed, string) {
	if s.Heads == nil {
		return nil, ""
	}
	out, err := s.Sys.Run("", "sysctl", "-n", "kern.disks")
	if err != nil {
		s.Log.Printf("seed: cannot list the disks: %v", err)
		return nil, ""
	}
	disks := strings.Fields(out)
	slices.Sort(disks)
	var found *Seed
	disk := ""
	for _, d := range disks {
		if strings.HasPrefix(d, "cd") {
			continue
		}
		b, err := s.Heads.ReadHead(d, SeedSize)
		if err != nil {
			continue
		}
		sd, err := ParseSeed(b)
		switch {
		case errors.Is(err, ErrNotSeed):
		case err != nil:
			s.Log.Printf("seed on %s ignored: %v", d, err)
		case found != nil:
			s.Log.Printf("seed on %s ignored: %s has one already", d, disk)
		default:
			found, disk = sd, d
		}
	}
	return found, disk
}

// UseSeed looks for the seed disk and, when there is one, adopts it (state.json is written
// only when something changes) and remembers it. Called once at the start.
func (s *Server) UseSeed(fresh bool) *Seed {
	sd, disk := s.findSeed()
	if sd == nil {
		return nil
	}
	s.mu.Lock()
	st := s.st.Clone()
	if AdoptSeed(st, sd, fresh) {
		if err := SaveState(s.Sys, s.Data, st); err != nil {
			s.Log.Printf("seed: saving the state: %v", err)
		}
		s.st = st
		s.Log.Printf("seed on %s: internal link on %s", disk, st.Listen)
	} else {
		s.Log.Printf("seed on %s: listen address already set", disk)
	}
	s.mu.Unlock()
	s.hmu.Lock()
	s.seed, s.seedDisk = sd, disk
	s.hmu.Unlock()
	if validZone(sd.Timezone) {
		s.keelTZ.Store(sd.Timezone)
	}
	return sd
}
