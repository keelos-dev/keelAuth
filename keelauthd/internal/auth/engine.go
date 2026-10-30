package auth

import (
	"os"
	"path/filepath"

	"keelauth/internal/engine"
	"keelauth/internal/sys"
)

// The account engines (docs/01 "2026-10-30 晚"): Kanidm in the VM, or keelauthd's own store.
const (
	EngineKanidm = "kanidm"
	EngineNative = "native"
	// DefaultEngine is what a new keelAuth gets: the native store since 2026-10-30 (its LDAP and
	// OIDC modules are in and verified); an existing keelAuth keeps the engine recorded in its
	// state (Kanidm stays in the image for those, docs/01).
	DefaultEngine = EngineNative
	AccountsFile  = "accounts.json" // the native engine's store, in DataDir
)

// ChooseEngine says which engine the data in dir belongs to: the state's record; else the
// engine whose data is there; else, for a new keelAuth, what the seed or the environment
// (KEELAUTHD_ENGINE) asks for; else the default. keelauthd serve calls it before NewServer.
func ChooseEngine(sy sys.Sys, dir string, wanted ...string) string {
	if st, _, err := LoadState(sy, dir); err == nil && st.Engine != "" {
		return st.Engine
	}
	if _, err := os.Stat(filepath.Join(dir, "kanidm", "kanidm.db")); err == nil {
		return EngineKanidm
	}
	if _, err := os.Stat(filepath.Join(dir, AccountsFile)); err == nil {
		return EngineNative
	}
	for _, w := range wanted {
		if w == EngineNative || w == EngineKanidm {
			return w
		}
	}
	return DefaultEngine
}

// native is the engine as the native store, nil with Kanidm (or the test fake).
func (s *Server) native() *engine.Native {
	n, _ := s.Eng.(*engine.Native)
	return n
}

// engineKind: the engine in use, as the state records it (the store's own kind before the
// state says).
func (s *Server) engineKind() string {
	if k := s.State().Engine; k != "" {
		return k
	}
	if s.native() != nil {
		return EngineNative
	}
	return EngineKanidm
}

// serviceNames are the system services keelauthd runs: kanidmd only with Kanidm.
func (s *Server) serviceNames() []string {
	if s.engineKind() == EngineNative {
		return []string{"radiusd"}
	}
	return []string{"kanidmd", "radiusd"}
}

// bindNative gives the native store the master key for the OIDC client secrets and the
// password rule; called once the key is open, and after the rule changed.
func (s *Server) bindNative() {
	n := s.native()
	if n == nil {
		return
	}
	n.Seal = func(v string) string {
		s.keyMu.Lock()
		defer s.keyMu.Unlock()
		if s.box == nil {
			return ""
		}
		return s.box.Seal(v)
	}
	n.Open = func(v string) (string, error) {
		s.keyMu.Lock()
		defer s.keyMu.Unlock()
		if s.box == nil {
			return "", errLocked
		}
		return s.box.Open(v)
	}
	s.applyPolicy()
}

// applyPolicy hands the password rule to the native store (Kanidm reads it from config.toml).
func (s *Server) applyPolicy() {
	if n := s.native(); n != nil {
		minLen, strength := s.State().PasswordPolicy()
		n.SetPolicy(engine.Policy{MinLength: minLen, Strength: strength})
	}
}
