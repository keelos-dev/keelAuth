package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/secret"
	"keelauth/internal/sys"
)

func init() { secret.PassIter = 1000 } // PBKDF2's real count is slow; the code path is the same

var testNow = time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

// The recovery key keel shows for an instance key: the same vector is in keelOS's
// keel/internal/web (TestAuthRecoveryKey), so both sides derive the same KEK.
func TestRecoveryKeyVector(t *testing.T) {
	kek, err := secret.KeelKEK("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	if err != nil {
		t.Fatal(err)
	}
	const want = "KAR1-OZOSX-ZCFKN-6ZEII-R7VUI-PKRDE-BFUIW-2KQ5D-UWRS5-PJU2A-6WD3J-G22JQ"
	if got := secret.RecoveryKey(kek); got != want {
		t.Fatalf("recovery key %s, want %s", got, want)
	}
	back, err := secret.ParseRecoveryKey(" kar1 ozosx-zcfkn 6zeii-r7vui-pkrde-bfuiw-2kq5d-uwrs5-pju2a-6wd3j-g22jq\n")
	if err != nil || !bytes.Equal(back, kek) {
		t.Fatalf("parse: %v", err)
	}
	if _, err := secret.ParseRecoveryKey(strings.Replace(want, "OZOSX", "OZOSY", 1)); err == nil {
		t.Error("a typo was not caught")
	}
	if _, err := secret.ParseRecoveryKey("Keel-Auth-2026"); err == nil {
		t.Error("a passphrase parsed as a recovery key")
	}
}

func TestWrapUnwrap(t *testing.T) {
	master := bytes.Repeat([]byte{7}, 32)
	k1, _ := secret.KeelKEK(strings.Repeat("ab", 32))
	k2, _ := secret.KeelKEK(strings.Repeat("cd", 32))
	w := &Wrapped{Version: 1, KeyID: keyID(master)}
	slot, err := sealSlot("keel", master, k1, testNow)
	if err != nil {
		t.Fatal(err)
	}
	w.put(slot)
	if !bytes.Equal(w.openKEK(k1), master) {
		t.Fatal("keel slot does not open with its KEK")
	}
	if w.openKEK(k2) != nil {
		t.Fatal("keel slot opens with another KEK")
	}
	if w.openPass("anything") != nil {
		t.Fatal("no passphrase slot, yet a passphrase opened it")
	}
	w2, err := ParseWrapped(w.marshal())
	if err != nil || !bytes.Equal(w2.openKEK(k1), master) {
		t.Fatalf("marshal round trip: %v", err)
	}
	if bytes.Contains(w.marshal(), master) || strings.Contains(string(w.marshal()), "0707070707") {
		t.Fatal("master key in clear in master.wrap")
	}
}

// legacyDisk is a data disk as keelauthd before the wrapping left it: master.key in clear, the
// seed's key in state.json, a user's NT hash and a backup with the clear key in it.
func legacyDisk(t *testing.T, seedKey string) (*sys.Fake, []byte) {
	sy := sys.NewFake()
	master := bytes.Repeat([]byte{0x5a}, 32)
	box, _ := secret.NewBox(master)
	st := &State{Key: seedKey, Domain: "auth.office.lan", Admin: box.Seal("adm-pw"),
		Users: map[string]*UserData{"anna": {NT: box.Seal(secret.NTHash("Keel-Auth-2026"))}}}
	st.normalize()
	sy.Files["/data/keelauth/master.key"] = master
	sy.Files["/data/keelauth/state.json"] = st.Marshal()
	old, err := writeBackupFiles(map[string][]byte{kanidmBackupName: []byte("KANIDM-DB"), stateFile: st.Marshal(), masterKeyFile: master},
		[]string{kanidmBackupName, stateFile, masterKeyFile}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	sy.Files["/data/keelauth/backups/keelauth-20261001T000000Z.tar.gz"] = old
	return sy, master
}

// noClearKey: no file anywhere under the data directory holds the master key in clear.
func noClearKey(t *testing.T, sy *sys.Fake, master []byte) {
	t.Helper()
	for p, b := range sy.Files {
		if !strings.HasPrefix(p, "/data/") {
			continue
		}
		if bytes.Contains(b, master) {
			t.Errorf("%s holds the master key in clear", p)
		}
		if strings.HasSuffix(p, ".tar.gz") {
			files, _, err := readBackupFiles(b)
			if err != nil {
				t.Errorf("%s: %v", p, err)
				continue
			}
			if files[masterKeyFile] != nil {
				t.Errorf("%s still has master.key", p)
			}
			for n, f := range files {
				if bytes.Contains(f, master) {
					t.Errorf("%s: %s holds the master key in clear", p, n)
				}
			}
		}
	}
}

// An existing data disk is migrated at the start: master.key wrapped with keel's key and
// removed, the internal key out of state.json, the old backups rewritten; secrets still open.
func TestMasterKeyMigration(t *testing.T) {
	key := strings.Repeat("ab", 32)
	sy, master := legacyDisk(t, key)
	s := startServer(t, sy, engine.NewFake(), testSeed(key))
	if s.Locked() {
		t.Fatal("locked after the migration")
	}
	if _, ok := sy.Files["/data/keelauth/master.key"]; ok {
		t.Error("master.key still on the data disk")
	}
	w, err := ParseWrapped(sy.Files["/data/keelauth/master.wrap"])
	if err != nil {
		t.Fatal(err)
	}
	kek, _ := secret.KeelKEK(key)
	if !bytes.Equal(w.openKEK(kek), master) {
		t.Error("master.wrap does not open with keel's key")
	}
	if strings.Contains(string(sy.Files["/data/keelauth/state.json"]), key) {
		t.Error("the internal key is still in state.json")
	}
	if nt, _ := s.box.Open(s.State().Users["anna"].NT); nt != secret.NTHash("Keel-Auth-2026") {
		t.Error("NT hash does not open after the migration")
	}
	if _, ok := sy.Files[LocalKeyFile]; ok {
		t.Error("a keel-managed keelAuth keeps a clear copy on the system disk")
	}
	noClearKey(t, sy, master)
	// the internal link still takes keel's key (from the seed now)
	req := httptest.NewRequest("GET", "/v1/status", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Errorf("status with keel's key after the migration: %d", rec.Code)
	}
	// the next start opens it with the seed alone
	s2 := startServer(t, sy, engine.NewFake(), testSeed(key))
	if s2.Locked() || !bytes.Equal(s2.master, master) {
		t.Error("second start: not opened")
	}
}

// A backup on its own is useless: no clear key, no clear NT hash; another keelAuth cannot
// restore it without the recovery key, and can with it.
func TestBackupNeedsRecoveryKey(t *testing.T) {
	a := newRig(t)
	a.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026"})
	name := a.ok("POST", "/v1/backups", nil)["name"].(string)
	raw := a.sy.Files["/data/keelauth/backups/"+name]
	dl := httptest.NewRequest("GET", "/v1/backups/"+name, nil) // what the page's Download gets
	dl.Header.Set("Authorization", "Bearer "+a.key)
	drec := httptest.NewRecorder()
	a.h.ServeHTTP(drec, dl)
	if drec.Code != 200 || !bytes.Equal(drec.Body.Bytes(), raw) || !strings.Contains(drec.Header().Get("Content-Disposition"), name) {
		t.Fatalf("download: %d", drec.Code)
	}
	noClearKey(t, a.sy, a.s.master)
	files, _, err := readBackupFiles(raw)
	if err != nil {
		t.Fatal(err)
	}
	if files[wrapFile] == nil || files[masterKeyFile] != nil {
		t.Fatalf("backup files: %v", keys(files))
	}
	if strings.Contains(string(files[stateFile]), secret.NTHash("Keel-Auth-2026")) {
		t.Fatal("NT hash in clear in the backup")
	}
	// another host's keelAuth (another instance key)
	b := newRigKey(t, strings.Repeat("cd", 32))
	up := func() {
		req := httptest.NewRequest("POST", "/v1/backups/upload?name="+name, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer "+b.key)
		rec := httptest.NewRecorder()
		b.h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("upload: %d %s", rec.Code, rec.Body)
		}
	}
	up()
	if code, out, _ := b.call("POST", "/v1/backups/"+name+"/restore", "", nil); code != 400 || out["code"] != "need_recovery_key" {
		t.Fatalf("restore without the recovery key: %d %v", code, out)
	}
	kb, _ := secret.KeelKEK(b.key)
	if code, out, _ := b.call("POST", "/v1/backups/"+name+"/restore", "", map[string]any{"recovery_key": secret.RecoveryKey(kb)}); code != 400 || out["code"] != "bad_key" {
		t.Fatalf("restore with another keelAuth's recovery key: %d %v", code, out)
	}
	if _, err := b.eng.User("anna"); err == nil {
		t.Fatal("anna there before the restore")
	}
	ka, _ := secret.KeelKEK(a.key)
	b.ok("POST", "/v1/backups/"+name+"/restore", map[string]any{"recovery_key": secret.RecoveryKey(ka)})
	if nt, _ := b.s.box.Open(b.s.State().Users["anna"].NT); nt != secret.NTHash("Keel-Auth-2026") {
		t.Error("NT hash not readable after the restore with the recovery key")
	}
	if bytes.Equal(a.s.master, b.s.master) {
		t.Error("the restore took over the other keelAuth's master key")
	}
	// (the fake engine's "database restore" does not bring the users back, so RADIUS's file is
	// not checked here; TestBackupRestore does on the same keelAuth)
}

func keys(m map[string][]byte) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

// newRigKey is newRig with another instance key.
func newRigKey(t *testing.T, key string) *rig {
	r := newRig(t)
	// a fresh data disk under another seed
	sy := sys.NewFake()
	sy.Handle = r.sy.Handle
	eng := engine.NewFake()
	s := startServer(t, sy, eng, testSeed(key))
	s.update(func(st *State) error { st.Domain = "auth.office.lan"; return nil }, false)
	if err := s.BringUp(); err != nil {
		t.Fatal(err)
	}
	return &rig{t: t, s: s, sy: sy, eng: eng, h: s.Handler(), key: key}
}

// The data disk under a seed whose key does not open it: locked until the recovery key is given;
// then the new seed's key is the one it opens with.
func TestLockedUnlock(t *testing.T) {
	a := newRig(t)
	a.ok("POST", "/v1/users", map[string]any{"name": "anna", "password": "Keel-Auth-2026"})
	newKey := strings.Repeat("ef", 32)
	s := startServer(t, a.sy, a.eng, testSeed(newKey))
	if !s.Locked() {
		t.Fatal("not locked under another seed")
	}
	r := &rig{t: t, s: s, sy: a.sy, eng: a.eng, h: s.Handler(), key: newKey}
	if code, out, _ := r.call("GET", "/v1/users", "", nil); code != 503 || out["code"] != "locked" {
		t.Fatalf("users while locked: %d %v", code, out)
	}
	st := r.ok("GET", "/v1/status", nil)
	if mk, _ := st["master_key"].(map[string]any); mk["locked"] != true {
		t.Errorf("status master_key %v", st["master_key"])
	}
	if code, out, _ := r.call("POST", "/unlock", "none", map[string]any{"recovery_key": "KAR1-AAAAA"}); code != 400 {
		t.Fatalf("bad key: %d %v", code, out)
	}
	ka, _ := secret.KeelKEK(a.key)
	if code, out, _ := r.call("POST", "/unlock", "none", map[string]any{"recovery_key": secret.RecoveryKey(ka)}); code != 200 {
		t.Fatalf("unlock: %d %v", code, out)
	}
	if s.Locked() || !bytes.Equal(s.master, a.s.master) {
		t.Fatal("still locked")
	}
	if nt, _ := s.box.Open(s.State().Users["anna"].NT); nt != secret.NTHash("Keel-Auth-2026") {
		t.Error("NT hash")
	}
	// now the new seed opens it alone
	if s2 := startServer(t, a.sy, a.eng, testSeed(newKey)); s2.Locked() {
		t.Error("the new seed does not open it after the unlock")
	}
	if code, _, _ := r.call("POST", "/unlock", "none", map[string]any{"recovery_key": secret.RecoveryKey(ka)}); code != 409 {
		t.Errorf("unlock when not locked: %d", code)
	}
}

// Standalone: the key stays in master.key with a warning until a passphrase is set; then it is
// wrapped, the clear copy is on the system disk only, and a new system disk needs the
// passphrase.
func TestStandalonePassphrase(t *testing.T) {
	sy := sys.NewFake()
	eng := engine.NewFake()
	s := startServer(t, sy, eng, nil)
	if s.Locked() {
		t.Fatal("locked")
	}
	master := append([]byte{}, s.master...)
	if !bytes.Equal(sy.Files["/data/keelauth/master.key"], master) {
		t.Fatal("no master.key for a standalone keelAuth without a passphrase")
	}
	hasAlert := func(code string) bool {
		for _, a := range s.Alerts() {
			if a.Code == code {
				return true
			}
		}
		return false
	}
	if !hasAlert("master_key_unprotected") {
		t.Error("no warning while the key is not wrapped")
	}
	r := &rig{t: t, s: s, sy: sy, eng: eng, h: s.local(s.Handler())}
	s.starting.Store(false)
	if code, _, _ := r.call("PUT", "/v1/recovery", "none", map[string]any{"passphrase": "short"}); code != 400 {
		t.Errorf("short passphrase: %d", code)
	}
	r.ok("PUT", "/v1/recovery", map[string]any{"passphrase": "Copper Harbor 2958 Maple"})
	if _, ok := sy.Files["/data/keelauth/master.key"]; ok {
		t.Error("master.key still on the data disk")
	}
	if !bytes.Equal(sy.Files[LocalKeyFile], master) {
		t.Error("no clear copy on the system disk")
	}
	if hasAlert("master_key_unprotected") {
		t.Error("warning after the passphrase")
	}
	noClearKey(t, sy, master)
	if s2 := startServer(t, sy, eng, nil); s2.Locked() {
		t.Error("restart with the system disk's copy: locked")
	}
	// a new system disk
	delete(sy.Files, LocalKeyFile)
	s3 := startServer(t, sy, eng, nil)
	if !s3.Locked() {
		t.Fatal("not locked without the system disk's copy")
	}
	if err := s3.Unlock("", "wrong passphrase here"); err == nil {
		t.Fatal("wrong passphrase unlocked")
	}
	if err := s3.Unlock("", "Copper Harbor 2958 Maple"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s3.master, master) || !bytes.Equal(sy.Files[LocalKeyFile], master) {
		t.Error("unlocked, but not the key or no copy on the system disk again")
	}
}

// The zone the page gets: keel's header through keel, the seed's otherwise when managed,
// keelAuth's own setting standalone (default UTC).
func TestZone(t *testing.T) {
	r := newRig(t)
	get := func(hdr string) string {
		req := httptest.NewRequest("GET", "/session", nil)
		req.Header.Set("Authorization", "Bearer "+r.key)
		if hdr != "" {
			req.Header.Set(ZoneHeader, hdr)
		}
		rec := httptest.NewRecorder()
		r.h.ServeHTTP(rec, req)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		z, _ := out["timezone"].(string)
		return z
	}
	if z := get("Asia/Tokyo"); z != "Asia/Tokyo" {
		t.Errorf("through keel: %q", z)
	}
	if z := get("Not/AZone"); z != "UTC" {
		t.Errorf("bad header: %q", z)
	}
	r.s.SetKeelZone("Europe/Berlin")
	if z := get(""); z != "Europe/Berlin" {
		t.Errorf("keel's zone from the registration: %q", z)
	}
	// standalone
	sy := sys.NewFake()
	s := startServer(t, sy, engine.NewFake(), nil)
	h := s.local(s.Handler())
	call := func(method, path string, body any) map[string]any {
		var rd *bytes.Reader
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
		req := httptest.NewRequest(method, path, rd)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
		}
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if out := call("GET", "/v1/settings", nil); out["timezone"] != "UTC" || out["timezone_in_use"] != "UTC" {
		t.Errorf("default zone %v", out)
	}
	if out := call("PUT", "/v1/settings", map[string]any{"timezone": "Asia/Tokyo"}); out["timezone_in_use"] != "Asia/Tokyo" {
		t.Errorf("set zone %v", out)
	}
	req := httptest.NewRequest("PUT", "/v1/settings", strings.NewReader(`{"timezone":"Mars/Base"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Errorf("bad zone: %d", rec.Code)
	}
}
