package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"keelauth/internal/secret"
)

// The master key (docs/02 §2.1, keelOS docs/54 §6): 32 random bytes that seal state.json's
// secrets (NT hashes, idm_admin's password, RADIUS secrets, the LDAP bind password) and the
// web sessions. It is never in clear on the data disk or in a backup once it can be wrapped:
// the data disk holds master.wrap, the key sealed under one or more key-encryption keys:
//
//   - "keel": derived from the instance key on keel's seed disk (secret.KeelKEK). keel hands
//     the same KEK out as the instance's recovery key (KAR1-…), so that a backup can be
//     restored on another host;
//   - "passphrase": the recovery passphrase an administrator of a standalone keelAuth sets.
//
// A keelAuth managed by keel opens it with the seed at every start. A standalone one keeps a
// clear copy on its system disk (LocalKeyFile, not in backups) so that it starts unattended;
// until its administrator sets a passphrase the key stays in master.key on the data disk, and
// the page warns. When no key at hand opens master.wrap (the data disk under another seed, or
// a new system disk of a standalone keelAuth) keelauthd stays locked until someone gives the
// recovery key or the passphrase (POST /unlock, "keelauthd unlock").

const (
	wrapFile = "master.wrap"
	// LocalKeyFile: a standalone keelAuth's clear copy of the master key, on the system disk.
	LocalKeyFile  = "/var/db/keelauthd/master.key"
	minPassphrase = 12
)

// WrapSlot is the master key sealed under one KEK.
type WrapSlot struct {
	Kind   string `json:"kind"`           // keel | passphrase
	Salt   string `json:"salt,omitempty"` // passphrase: PBKDF2's salt, base64
	Iter   int    `json:"iter,omitempty"` // passphrase: PBKDF2's iterations
	Sealed string `json:"sealed"`         // secret.Box(KEK).Seal(hex(master key))
	Set    string `json:"set,omitempty"`  // when (RFC 3339)
}

// Wrapped is master.wrap.
type Wrapped struct {
	Version int        `json:"version"`
	KeyID   string     `json:"key_id"` // the start of the master key's SHA-256: which key this is
	Slots   []WrapSlot `json:"slots"`
}

func keyID(k []byte) string { s := sha256.Sum256(k); return hex.EncodeToString(s[:8]) }

func (w *Wrapped) has(kind string) bool {
	for _, s := range w.Slots {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func openSlot(s WrapSlot, kek []byte, id string) []byte {
	b, err := secret.NewBox(kek)
	if err != nil {
		return nil
	}
	h, err := b.Open(s.Sealed)
	if err != nil {
		return nil
	}
	k, err := hex.DecodeString(h)
	if err != nil || len(k) != 32 || keyID(k) != id {
		return nil
	}
	return k
}

// openKEK: the master key from a keel slot that kek opens; nil when none does.
func (w *Wrapped) openKEK(kek []byte) []byte {
	for _, s := range w.Slots {
		if s.Kind == "keel" {
			if k := openSlot(s, kek, w.KeyID); k != nil {
				return k
			}
		}
	}
	return nil
}

// openPass: the master key from a passphrase slot.
func (w *Wrapped) openPass(pass string) []byte {
	for _, s := range w.Slots {
		if s.Kind != "passphrase" {
			continue
		}
		salt, err := base64.StdEncoding.DecodeString(s.Salt)
		if err != nil || s.Iter < 1 {
			continue
		}
		kek, err := secret.PassKEK(pass, salt, s.Iter)
		if err != nil {
			continue
		}
		if k := openSlot(s, kek, w.KeyID); k != nil {
			return k
		}
	}
	return nil
}

// put replaces the slots of slot's kind with slot.
func (w *Wrapped) put(slot WrapSlot) {
	out := []WrapSlot{}
	for _, s := range w.Slots {
		if s.Kind != slot.Kind {
			out = append(out, s)
		}
	}
	w.Slots = append(out, slot)
}

func sealSlot(kind string, master, kek []byte, now time.Time) (WrapSlot, error) {
	b, err := secret.NewBox(kek)
	if err != nil {
		return WrapSlot{}, err
	}
	return WrapSlot{Kind: kind, Sealed: b.Seal(hex.EncodeToString(master)), Set: now.Format(time.RFC3339)}, nil
}

// ParseWrapped reads master.wrap.
func ParseWrapped(b []byte) (*Wrapped, error) {
	w := &Wrapped{}
	if err := json.Unmarshal(b, w); err != nil {
		return nil, err
	}
	if w.Version != 1 || len(w.KeyID) != 16 {
		return nil, errors.New("not a master.wrap of version 1")
	}
	return w, nil
}

func (w *Wrapped) marshal() []byte {
	b, _ := json.MarshalIndent(w, "", "  ")
	return append(b, '\n')
}

func (s *Server) dataPath(n string) string { return filepath.Join(s.Data, n) }

func (s *Server) localKeyPath() string {
	if s.LocalKey != "" {
		return s.LocalKey
	}
	return LocalKeyFile
}

// read32 reads a 32-byte key file: nil when it is not there or not 32 bytes.
func (s *Server) read32(p string) ([]byte, error) {
	b, err := s.Sys.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		s.Log.Printf("master key: %s is not 32 bytes: ignored", p)
		return nil, nil
	}
	return b, nil
}

func (s *Server) readWrap() (*Wrapped, error) {
	b, err := s.Sys.ReadFile(s.dataPath(wrapFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	w, err := ParseWrapped(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", s.dataPath(wrapFile), err)
	}
	return w, nil
}

// Locked: the master key is not open (no key at hand opens master.wrap).
func (s *Server) Locked() bool { return !s.unlocked.Load() }

// OpenMasterKey opens the master key at the start (sd: the seed, nil for a standalone keelAuth),
// making it the first time and wrapping a clear one (migration from master.key: automatic). When
// nothing at hand opens it keelauthd stays locked (an error is only for what cannot be read).
func (s *Server) OpenMasterKey(sd *Seed) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	s.kek = nil
	if sd != nil {
		kek, err := secret.KeelKEK(sd.Key)
		if err != nil {
			return err
		}
		s.kek = kek
	}
	w, err := s.readWrap()
	if err != nil {
		return err
	}
	plain, err := s.read32(s.dataPath(masterKeyFile))
	if err != nil {
		return err
	}
	var master []byte
	how := ""
	switch {
	case w != nil:
		if s.kek != nil {
			master, how = w.openKEK(s.kek), "keel's seed"
		}
		if master == nil {
			if c, _ := s.read32(s.localKeyPath()); c != nil && keyID(c) == w.KeyID {
				master, how = c, "its copy on the system disk"
			}
		}
		if master == nil && plain != nil && keyID(plain) == w.KeyID { // a migration cut short
			master, how = plain, "master.key"
		}
	case plain != nil:
		master, how = plain, "master.key"
	default:
		master, how = make([]byte, 32), "a new key"
		if _, err := rand.Read(master); err != nil {
			return err
		}
	}
	if master == nil {
		what := "a seed whose key does not open it (the data disk of another keelAuth?)"
		if sd == nil {
			what = "no seed disk and no copy of the key on this system disk"
		}
		s.Log.Printf("master key: LOCKED: master.wrap (slots: %s) and %s; give the recovery key or the passphrase "+
			"on the web page or with \"keelauthd unlock\"", slotKinds(w), what)
		return nil
	}
	s.Log.Printf("master key: opened with %s", how)
	return s.useMaster(master, w)
}

func slotKinds(w *Wrapped) string {
	var k []string
	for _, s := range w.Slots {
		k = append(k, s.Kind)
	}
	if len(k) == 0 {
		return "none"
	}
	return strings.Join(k, ", ")
}

// useMaster takes master as the key (s.keyMu held) and stores it as this keelAuth wants it:
// managed by keel: wrapped with keel's KEK, nothing in clear anywhere; standalone with a
// passphrase: wrapped, a clear copy on the system disk; standalone without: master.key (the
// page warns). The backups are rewritten to match (no clear key in them once it is wrapped).
func (s *Server) useMaster(master []byte, w *Wrapped) error {
	box, err := secret.NewBox(master)
	if err != nil {
		return err
	}
	id := keyID(master)
	if w == nil || w.KeyID != id {
		w = &Wrapped{Version: 1, KeyID: id}
	}
	changed := false
	if _, err := s.Sys.ReadFile(s.dataPath(wrapFile)); err != nil {
		changed = true
	}
	if s.kek != nil && w.openKEK(s.kek) == nil {
		slot, err := sealSlot("keel", master, s.kek, s.now())
		if err != nil {
			return err
		}
		w.put(slot) // the slot of an earlier seed goes: one keel, the current one
		changed = true
	}
	if len(w.Slots) > 0 {
		if changed {
			if err := s.Sys.WriteFile(s.dataPath(wrapFile), w.marshal(), 0o600); err != nil {
				return err
			}
			s.Log.Printf("master key: wrapped (%s) in %s", slotKinds(w), s.dataPath(wrapFile))
		}
		if _, err := s.Sys.ReadFile(s.dataPath(masterKeyFile)); err == nil {
			if err := s.Sys.Remove(s.dataPath(masterKeyFile)); err != nil {
				return err
			}
			s.Log.Printf("master key: the clear master.key is off the data disk (migrated)")
		}
		lp := s.localKeyPath()
		cur, _ := s.Sys.ReadFile(lp)
		switch {
		case s.kek == nil && !bytes.Equal(cur, master): // standalone: starts unattended from the system disk
			if err := s.Sys.WriteFile(lp, master, 0o600); err != nil {
				return err
			}
		case s.kek != nil && cur != nil: // keel's seed opens it: no clear copy anywhere
			s.Sys.Remove(lp)
		}
	} else if _, err := s.Sys.ReadFile(s.dataPath(masterKeyFile)); err != nil { // standalone, no passphrase yet
		if err := s.Sys.WriteFile(s.dataPath(masterKeyFile), master, 0o600); err != nil {
			return err
		}
	}
	s.master, s.box, s.mwrap = master, box, w
	s.unlocked.Store(true)
	s.unlockOnce.Do(func() { close(s.unlockedCh) })
	s.loadSessions()
	s.migrateBackups()
	return nil
}

// wrapped: the master key is wrapped (no clear copy on the data disk).
func (s *Server) wrapped() bool {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	return s.mwrap != nil && len(s.mwrap.Slots) > 0
}

// keyFiles: the master key's file for a backup: master.wrap, or master.key while it is not
// wrapped (a standalone keelAuth without a passphrase).
func (s *Server) keyFile() (string, []byte, error) {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.mwrap != nil && len(s.mwrap.Slots) > 0 {
		return wrapFile, s.mwrap.marshal(), nil
	}
	if s.master == nil {
		return "", nil, errLocked
	}
	return masterKeyFile, append([]byte{}, s.master...), nil
}

// migrateBackups rewrites the backups that hold the master key in clear (made before it was
// wrapped) with master.wrap; one made under another key has its state.json sealed again under
// this one first.
func (s *Server) migrateBackups() {
	if s.mwrap == nil || len(s.mwrap.Slots) == 0 {
		return
	}
	bs, err := s.backups()
	if err != nil {
		return
	}
	n := 0
	for _, b := range bs {
		p := filepath.Join(s.backupDir(), b.Name)
		raw, err := s.Sys.ReadFile(p)
		if err != nil {
			continue
		}
		files, order, err := readBackupFiles(raw)
		if err != nil || files[masterKeyFile] == nil {
			continue
		}
		old := files[masterKeyFile]
		if !bytes.Equal(old, s.master) {
			from, err := secret.NewBox(old)
			st, perr := ParseState(files[stateFile])
			if err != nil || perr != nil || reseal(st, from, s.box) != nil {
				s.Log.Printf("master key: backup %s: cannot seal it under this key: left as it is", b.Name)
				continue
			}
			files[stateFile] = st.Marshal()
		}
		delete(files, masterKeyFile)
		files[wrapFile] = s.mwrap.marshal()
		var names []string
		for _, n := range order {
			if n != masterKeyFile {
				names = append(names, n)
			}
		}
		names = append(names, wrapFile)
		out, err := writeBackupFiles(files, names, s.now())
		if err == nil {
			err = s.Sys.WriteFile(p, out, 0o600)
		}
		if err != nil {
			s.Log.Printf("master key: backup %s: %v", b.Name, err)
			continue
		}
		n++
	}
	if n > 0 {
		s.Log.Printf("master key: %d backup(s) rewritten without the clear key", n)
	}
}

var errLocked = coded(http.StatusServiceUnavailable, "locked",
	"keelAuth is locked: its master key needs the recovery key (keelOS: Accounts → Recovery key) or its recovery passphrase")

// Unlock opens a locked master key with a recovery key (KAR1-…) or a passphrase.
func (s *Server) Unlock(recovery, pass string) error {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.unlocked.Load() {
		return conflict("keelAuth is not locked")
	}
	w, err := s.readWrap()
	if err != nil {
		return err
	}
	if w == nil {
		return conflict("there is no master.wrap to unlock")
	}
	var master []byte
	if recovery != "" {
		kek, err := secret.ParseRecoveryKey(recovery)
		if err != nil {
			return coded(http.StatusBadRequest, "bad_key", "%v", err)
		}
		master = w.openKEK(kek)
	}
	if master == nil && pass != "" {
		master = w.openPass(pass)
	}
	if master == nil {
		return coded(http.StatusBadRequest, "bad_key", "this does not open the master key (slots: %s)", slotKinds(w))
	}
	s.Log.Printf("master key: unlocked with a %s", map[bool]string{true: "recovery key", false: "passphrase"}[recovery != ""])
	return s.useMaster(master, w)
}

// SetPassphrase adds (or replaces) the passphrase slot. On a standalone keelAuth this is what
// takes the clear key off the data disk.
func (s *Server) SetPassphrase(pass string) error {
	if len([]rune(pass)) < minPassphrase {
		return bad("the recovery passphrase needs at least %d characters", minPassphrase)
	}
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	if s.master == nil {
		return errLocked
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	kek, err := secret.PassKEK(pass, salt, secret.PassIter)
	if err != nil {
		return err
	}
	slot, err := sealSlot("passphrase", s.master, kek, s.now())
	if err != nil {
		return err
	}
	slot.Salt, slot.Iter = base64.StdEncoding.EncodeToString(salt), secret.PassIter
	w := *s.mwrap
	w.Slots = append([]WrapSlot{}, s.mwrap.Slots...)
	w.put(slot)
	if err := s.Sys.WriteFile(s.dataPath(wrapFile), w.marshal(), 0o600); err != nil {
		return err
	}
	s.Log.Printf("master key: recovery passphrase set")
	return s.useMaster(s.master, &w)
}

// MasterKeyInfo is the status's master_key.
type MasterKeyInfo struct {
	Locked      bool     `json:"locked"`
	Slots       []string `json:"slots"`       // keel, passphrase
	Unprotected bool     `json:"unprotected"` // in clear on the data disk (standalone, no passphrase)
	Passphrase  string   `json:"passphrase_set,omitempty"`
}

func (s *Server) masterKeyInfo() MasterKeyInfo {
	s.keyMu.Lock()
	defer s.keyMu.Unlock()
	out := MasterKeyInfo{Locked: !s.unlocked.Load(), Slots: []string{}}
	w := s.mwrap
	if w == nil {
		w, _ = s.readWrap()
	}
	if w != nil {
		for _, sl := range w.Slots {
			out.Slots = append(out.Slots, sl.Kind)
			if sl.Kind == "passphrase" {
				out.Passphrase = sl.Set
			}
		}
	}
	out.Unprotected = !out.Locked && len(out.Slots) == 0
	return out
}

// ---- HTTP ----

func (s *Server) postUnlock(r *http.Request) (any, error) {
	var req struct {
		RecoveryKey string `json:"recovery_key"`
		Passphrase  string `json:"passphrase"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.RecoveryKey == "" && req.Passphrase == "" {
		return nil, bad("give recovery_key or passphrase")
	}
	now := s.now()
	if s.sessions.blocked("#unlock", now) {
		return nil, coded(http.StatusTooManyRequests, "wait", "too many wrong keys: wait 5 minutes")
	}
	if err := s.Unlock(strings.TrimSpace(req.RecoveryKey), req.Passphrase); err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Code == "bad_key" {
			s.sessions.fail("#unlock", now)
		}
		return nil, err
	}
	s.sessions.ok("#unlock")
	return map[string]any{"ok": true}, nil
}

func (s *Server) putRecovery(r *http.Request) (any, error) {
	var req struct {
		Passphrase string `json:"passphrase"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.SetPassphrase(req.Passphrase); err != nil {
		return nil, err
	}
	return s.masterKeyInfo(), nil
}
