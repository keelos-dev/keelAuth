package auth

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"keelauth/internal/secret"
)

// Backups (docs/02 section 3.3): one .tar.gz holds Kanidm's database backup, state.json and
// master.wrap: the master key wrapped (masterkey.go), never in clear once it can be wrapped.
// Without keel's seed, the recovery key or the passphrase the NT hashes in it are unreadable. They stay in
// <data>/backups (root only), the newest backup_keep of them. Once a day automatically.

const (
	kanidmBackupName = "kanidm.backup"
	backupEvery      = 24 * time.Hour
)

var backupRE = regexp.MustCompile(`^keelauth-(\d{8}T\d{6}Z)\.tar\.gz$`)

type BackupOut struct {
	Name string `json:"name"`
	Time string `json:"time"`
	Size int64  `json:"size"`
}

func (s *Server) backupDir() string { return filepath.Join(s.Data, "backups") }

func (s *Server) backups() ([]BackupOut, error) {
	es, err := s.Sys.ListDir(s.backupDir())
	if err != nil {
		return nil, err
	}
	out := []BackupOut{}
	for _, e := range es {
		m := backupRE.FindStringSubmatch(e.Name)
		if m == nil {
			continue
		}
		t, err := time.Parse("20060102T150405Z", m[1])
		if err != nil {
			continue
		}
		out = append(out, BackupOut{Name: e.Name, Time: t.Format(time.RFC3339), Size: e.Size})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name }) // newest first
	return out, nil
}

// Backup makes one backup now.
func (s *Server) Backup() (*BackupOut, error) {
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	now := s.now()
	name := "keelauth-" + now.Format("20060102T150405Z") + ".tar.gz"
	tmp := filepath.Join(s.backupDir(), ".kanidm-"+now.Format("20060102T150405Z")+".json.gz")
	if _, err := s.Sys.Run("", "install", "-d", "-m", "0700", s.backupDir()); err != nil {
		s.Log.Printf("backup: %v", err)
	}
	// the accounts: Kanidm's database backup, or the native store's file
	engName, kb := AccountsFile, []byte(nil)
	if n := s.native(); n != nil {
		kb = n.Export()
	} else {
		engName = kanidmBackupName
		if _, err := s.Sys.Run("", KanidmBin, "database", "backup", "-c", KanidmConf, tmp); err != nil {
			return nil, fmt.Errorf("kanidm backup: %v", err)
		}
		var err error
		kb, err = s.Sys.ReadFile(tmp)
		s.Sys.Remove(tmp)
		if err != nil {
			return nil, fmt.Errorf("kanidm backup: %v", err)
		}
	}
	st, err := s.Sys.ReadFile(filepath.Join(s.Data, stateFile))
	if err != nil {
		return nil, err
	}
	kn, kb2, err := s.keyFile()
	if err != nil {
		return nil, err
	}
	out, err := writeBackupFiles(map[string][]byte{engName: kb, stateFile: st, kn: kb2}, []string{engName, stateFile, kn}, now)
	if err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(out)
	if err := s.Sys.WriteFile(filepath.Join(s.backupDir(), name), buf.Bytes(), 0o600); err != nil {
		return nil, err
	}
	s.update(func(st *State) error { st.LastBackup = now.Format(time.RFC3339); return nil }, false)
	s.prune()
	s.Log.Printf("backup %s (%d bytes)", name, buf.Len())
	return &BackupOut{Name: name, Time: now.Format(time.RFC3339), Size: int64(buf.Len())}, nil
}

// prune keeps the newest backup_keep backups.
func (s *Server) prune() {
	bs, err := s.backups()
	if err != nil {
		return
	}
	for i, b := range bs {
		if i >= s.State().BackupKeep {
			if err := s.Sys.Remove(filepath.Join(s.backupDir(), b.Name)); err != nil {
				s.Log.Printf("backup: remove %s: %v", b.Name, err)
			}
		}
	}
}

// writeBackupFiles packs files (in the order of names) into a .tar.gz.
func writeBackupFiles(files map[string][]byte, names []string, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, n := range names {
		b := files[n]
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: int64(len(b)), ModTime: now}); err != nil {
			return nil, err
		}
		if _, err := tw.Write(b); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readBackupFiles unpacks a backup: Kanidm's database, state.json and the master key's file
// (master.wrap; master.key in one made before the key was wrapped), and the order they came in.
func readBackupFiles(b []byte) (map[string][]byte, []string, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, nil, err
	}
	tr := tar.NewReader(zr)
	out := map[string][]byte{}
	var order []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		v, err := io.ReadAll(io.LimitReader(tr, 256<<20))
		if err != nil {
			return nil, nil, err
		}
		if out[h.Name] == nil {
			order = append(order, h.Name)
		}
		out[h.Name] = v
	}
	if out[stateFile] == nil {
		return nil, nil, fmt.Errorf("the backup has no %s", stateFile)
	}
	if out[kanidmBackupName] == nil && out[AccountsFile] == nil {
		return nil, nil, fmt.Errorf("the backup has no %s", kanidmBackupName)
	}
	if out[wrapFile] == nil && out[masterKeyFile] == nil {
		return nil, nil, fmt.Errorf("the backup has no %s", wrapFile)
	}
	return out, order, nil
}

// reseal re-encrypts every secret of st from one master key to another.
func reseal(st *State, from, to *secret.Box) error {
	re := func(v *string) error {
		p, err := from.Open(*v)
		if err != nil {
			return err
		}
		*v = to.Seal(p)
		return nil
	}
	for _, u := range st.Users {
		if err := re(&u.NT); err != nil {
			return err
		}
	}
	for i := range st.Radius.Clients {
		if err := re(&st.Radius.Clients[i].Secret); err != nil {
			return err
		}
	}
	for _, v := range []*string{&st.Admin, &st.BindPW, &st.Radius.Local} {
		if err := re(v); err != nil {
			return err
		}
	}
	return nil
}

// backupKey opens the master key a backup's state.json is sealed under: its master.key (an
// old backup), or its master.wrap with this keelAuth's own key (the same keelAuth, or keel's
// seed), a recovery key or a passphrase. Without one of those the backup's NT hashes and other
// secrets cannot be read: 400 code need_recovery_key.
func (s *Server) backupKey(files map[string][]byte, recovery, pass string) (*secret.Box, error) {
	if k := files[masterKeyFile]; k != nil {
		return secret.NewBox(k)
	}
	w, err := ParseWrapped(files[wrapFile])
	if err != nil {
		return nil, bad("the backup's %s: %v", wrapFile, err)
	}
	s.keyMu.Lock()
	var mk []byte
	if s.master != nil && keyID(s.master) == w.KeyID {
		mk = s.master
	}
	if mk == nil && s.kek != nil {
		mk = w.openKEK(s.kek)
	}
	s.keyMu.Unlock()
	if mk == nil && recovery != "" {
		kek, err := secret.ParseRecoveryKey(recovery)
		if err != nil {
			return nil, coded(http.StatusBadRequest, "bad_key", "%v", err)
		}
		if mk = w.openKEK(kek); mk == nil {
			return nil, coded(http.StatusBadRequest, "bad_key", "this recovery key is not the one of the keelAuth that made the backup")
		}
	}
	if mk == nil && pass != "" {
		if mk = w.openPass(pass); mk == nil {
			return nil, coded(http.StatusBadRequest, "bad_key", "this passphrase does not open the backup")
		}
	}
	if mk == nil {
		return nil, coded(http.StatusBadRequest, "need_recovery_key",
			"this backup was made by another keelAuth: give its recovery key (keelOS: Accounts → Recovery key) or its recovery passphrase (slots: %s)", slotKinds(w))
	}
	return secret.NewBox(mk)
}

// Restore puts a backup back: Kanidm's database (Kanidm stopped meanwhile) and keelauthd's
// data, sealed again under this keelAuth's master key, keeping its listen addresses and the
// access to it (tokens, sync keys). A backup of another keelAuth needs its recovery key or
// passphrase (backupKey).
func (s *Server) Restore(name, recovery, pass string) error {
	if !backupRE.MatchString(name) {
		return notFound("no backup %q", name)
	}
	if s.Locked() {
		return errLocked
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	b, err := s.Sys.ReadFile(filepath.Join(s.backupDir(), name))
	if err != nil {
		return notFound("no backup %q", name)
	}
	files, _, err := readBackupFiles(b)
	if err != nil {
		return fmt.Errorf("backup %s: %v", name, err)
	}
	old, err := ParseState(files[stateFile])
	if err != nil {
		return fmt.Errorf("backup %s: state.json: %v", name, err)
	}
	from, err := s.backupKey(files, recovery, pass)
	if err != nil {
		return err
	}
	if err := reseal(old, from, s.box); err != nil {
		return coded(http.StatusBadRequest, "bad_key", "backup %s: %v", name, err)
	}
	// the accounts go back into the engine the backup came from; a backup of the other engine
	// is a migration, not a restore
	switch n := s.native(); {
	case n != nil && files[AccountsFile] == nil:
		return bad("backup %s holds Kanidm's database: this keelAuth keeps its accounts itself (migrate it first)", name)
	case n == nil && files[kanidmBackupName] == nil:
		return bad("backup %s holds keelAuth's own account store: this keelAuth runs Kanidm", name)
	case n != nil:
		// the secrets in it are sealed under the backup's key: reseal through the state's box pair
		if err := n.Import(files[AccountsFile], from, s.box); err != nil {
			return fmt.Errorf("accounts: %v", err)
		}
	default:
		tmp := filepath.Join(s.backupDir(), ".restore-kanidm.json.gz") // Kanidm takes it as gzip by the name
		if err := s.Sys.WriteFile(tmp, files[kanidmBackupName], 0o600); err != nil {
			return err
		}
		defer s.Sys.Remove(tmp)
		s.Sys.Run("", "service", "kanidmd", "onestop")
		if _, err := s.Sys.Run("", KanidmBin, "database", "restore", "-c", KanidmConf, tmp); err != nil {
			s.Sys.Run("", "service", "kanidmd", "onestart")
			return fmt.Errorf("kanidm restore: %v", err)
		}
		s.Sys.Run("", "chown", "-R", "kanidmd:kanidmd", s.kanidmDir())
	}
	err = s.update(func(st *State) error {
		old.Key = ""
		old.Listen, old.HTTPSListen = st.Listen, st.HTTPSListen
		old.Tokens, old.SyncKeys = st.Tokens, st.SyncKeys // access to keelAuth stays as it is now
		old.LastBackup = st.LastBackup
		old.Revision = st.Revision + 1
		old.Engine = st.Engine
		if old.Timezone == "" {
			old.Timezone = st.Timezone
		}
		*st = *old
		st.normalize()
		return nil
	}, false)
	if err != nil {
		return err
	}
	s.sessions.clear()
	if s.native() == nil {
		if _, err := s.Sys.Run("", "service", "kanidmd", "onestart"); err != nil {
			return err
		}
	}
	s.Log.Printf("restored %s", name)
	return s.BringUp()
}

// Upload takes a backup made elsewhere (another host, an older copy) into the backups
// directory: it must be a keelAuth backup; restoring it is a separate step.
func (s *Server) Upload(name string, b []byte) (*BackupOut, error) {
	if name == "" {
		name = "keelauth-" + s.now().Format("20060102T150405Z") + ".tar.gz"
	}
	m := backupRE.FindStringSubmatch(name)
	if m == nil {
		return nil, bad("name: keelauth-YYYYMMDDTHHMMSSZ.tar.gz")
	}
	if _, _, err := readBackupFiles(b); err != nil {
		return nil, bad("not a keelAuth backup: %v", err)
	}
	s.backupMu.Lock()
	defer s.backupMu.Unlock()
	p := filepath.Join(s.backupDir(), name)
	if _, err := s.Sys.ReadFile(p); err == nil {
		return nil, conflict("there is a backup %s already", name)
	}
	if err := s.Sys.WriteFile(p, b, 0o600); err != nil {
		return nil, err
	}
	t, _ := time.Parse("20060102T150405Z", m[1])
	s.Log.Printf("backup %s uploaded (%d bytes)", name, len(b))
	return &BackupOut{Name: name, Time: t.Format(time.RFC3339), Size: int64(len(b))}, nil
}

// getBackupFile downloads one backup (to keep elsewhere or restore on another keelAuth: its
// secrets stay sealed, the recovery key opens them there).
func (s *Server) getBackupFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !backupRE.MatchString(name) {
		writeErr(w, notFound("no backup %q", name))
		return
	}
	b, err := s.Sys.ReadFile(filepath.Join(s.backupDir(), name))
	if err != nil {
		writeErr(w, notFound("no backup %q", name))
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (s *Server) postUpload(r *http.Request) (any, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, maxUpload+1))
	if err != nil {
		return nil, bad("cannot read the upload: %v", err)
	}
	if len(b) > maxUpload {
		return nil, bad("a backup is at most %d MiB", maxUpload>>20)
	}
	return s.Upload(r.URL.Query().Get("name"), b)
}

const maxUpload = 256 << 20

func (s *Server) getBackups(r *http.Request) (any, error) {
	bs, err := s.backups()
	if err != nil {
		return nil, err
	}
	return map[string]any{"backups": bs, "keep": s.State().BackupKeep, "dir": s.backupDir()}, nil
}

func (s *Server) postBackup(r *http.Request) (any, error) { return s.Backup() }

func (s *Server) postRestore(r *http.Request) (any, error) {
	var req struct {
		RecoveryKey string `json:"recovery_key"`
		Passphrase  string `json:"passphrase"`
	}
	if err := decodeOpt(r, &req); err != nil {
		return nil, err
	}
	if err := s.Restore(r.PathValue("name"), strings.TrimSpace(req.RecoveryKey), req.Passphrase); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

// Schedule runs the daily backup and renews the certificates when they near their end (checked
// every ten minutes), and every minute starts a service again whose process has gone (logged;
// the status and the alerts say so until it is up).
func (s *Server) Schedule() {
	for i := 0; ; i++ {
		if i%10 == 0 {
			st := s.State()
			last, err := time.Parse(time.RFC3339, st.LastBackup)
			if s.engineReady() && (err != nil || s.now().Sub(last) >= backupEvery) {
				if _, err := s.Backup(); err != nil {
					s.Log.Printf("scheduled backup: %v", err)
				}
			}
			if s.Real {
				if ch, err := s.EnsureTLS(st.Domain, s.internalIP()); err == nil {
					if ch.Server && s.engineKind() != EngineNative {
						s.Sys.Run("", "service", "kanidmd", "onerestart")
					}
					if ch.Radius {
						s.Sys.Run("", "service", "radiusd", "onerestart")
					}
				}
			}
		}
		if s.Real {
			s.restartGone()
		}
		time.Sleep(time.Minute)
	}
}

// restartGone starts kanidmd or radiusd again when its process is not running.
func (s *Server) restartGone() {
	// not while a backup or a restore runs (a restore stops kanidmd on purpose)
	if !s.backupMu.TryLock() {
		return
	}
	defer s.backupMu.Unlock()
	for _, svc := range s.serviceNames() {
		if s.running(svc) {
			continue
		}
		s.Log.Printf("%s is not running: starting it again", svc)
		var err error
		if svc == "kanidmd" {
			err = s.StartKanidm(false)
		} else {
			err = s.ApplyRadius()
		}
		if err != nil {
			s.Log.Printf("%s: %v", svc, err)
		}
	}
	if r := s.waitServices(); allUp(r) {
		s.hmu.Lock()
		eerr := s.engineErr
		s.hmu.Unlock()
		if eerr != nil {
			s.BringUp() // Kanidm is back: let keelauthd use it again
		}
	}
}

func (s *Server) engineReady() bool {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	return s.engineErr == nil
}
