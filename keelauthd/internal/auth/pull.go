package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Snapshots of the data disk and their fetching by a backup machine (docs/02 §3.3a, keelNAS
// docs/08-backup-pull.md; the same as keelMail's snapshot.go + pull.go). keelauthd takes a
// recursive ZFS snapshot of the dataset under /data ("kadata") every hour and every day and
// keeps the newest SnapHourly / SnapDaily; the daily one is taken right after a settings
// backup (backup.go), so every daily snapshot holds a consistent database dump next to the
// live files. A backup machine (keelNAS) fetches the daily snapshots with a read-only pull
// token on the HTTPS port under /backup/v1/; with the TLS server name BackupSNI it is given
// keelAuth's own certificate, the one the token pins (an imported certificate may change).

const (
	DefaultSnapHourly = 24
	DefaultSnapDaily  = 30
	snapHourly        = "keel-h-" // + UTC 20061102T15Z
	snapDaily         = "keel-d-" // + the date in the page's time zone
	snapManual        = "keel-m-" // + UTC 20060102T150405Z
	BackupSNI         = "keelbackup.invalid"
	pullTokenPrefix   = "kbk1"
	pullStale         = 48 * time.Hour
)

// PullState: the pull token (only its hash) and the last fetch.
type PullState struct {
	Allow     []string `json:"allow,omitempty"`      // source addresses (IPv4 or CIDR); empty = not limited
	TokenHash string   `json:"token_hash,omitempty"` // hex sha256 of the token's secret part
	TokenAt   string   `json:"token_at,omitempty"`
	TokenCert string   `json:"token_cert,omitempty"` // the certificate (sha256 hex) the token pins
	LastAt    string   `json:"last_at,omitempty"`
	LastSnap  string   `json:"last_snap,omitempty"`
	LastFrom  string   `json:"last_from,omitempty"`
}

func (s *Server) snapKeep() (hourly, daily int) {
	st := s.State()
	hourly, daily = DefaultSnapHourly, DefaultSnapDaily
	if st.SnapHourly != nil {
		hourly = *st.SnapHourly
	}
	if st.SnapDaily != nil {
		daily = *st.SnapDaily
	}
	return
}

// dataDataset is the ZFS dataset mounted on /data ("kadata"; "" when /data is no dataset).
func (s *Server) dataDataset() string {
	out, err := s.Sys.Run("", "zfs", "list", "-H", "-o", "name", "/data")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

type Snapshot struct {
	Name string    `json:"name"` // the part after @
	Kind string    `json:"kind"` // hourly, daily, manual
	Time time.Time `json:"time"`
	Used int64     `json:"used"` // bytes only this snapshot holds
}

func snapKind(n string) string {
	switch {
	case strings.HasPrefix(n, snapHourly):
		return "hourly"
	case strings.HasPrefix(n, snapDaily):
		return "daily"
	case strings.HasPrefix(n, snapManual):
		return "manual"
	}
	return ""
}

// snapshots lists keelauthd's snapshots of ds, oldest first.
func (s *Server) snapshots(ds string) ([]Snapshot, error) {
	out, err := s.Sys.Run("", "zfs", "list", "-H", "-p", "-t", "snapshot", "-o", "name,creation,used", "-d", "1", ds)
	if err != nil {
		return nil, fmt.Errorf("zfs list: %v", err)
	}
	var l []Snapshot
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			continue
		}
		_, name, ok := strings.Cut(f[0], "@")
		if !ok || snapKind(name) == "" {
			continue
		}
		c, _ := strconv.ParseInt(f[1], 10, 64)
		u, _ := strconv.ParseInt(f[2], 10, 64)
		l = append(l, Snapshot{name, snapKind(name), time.Unix(c, 0).UTC(), u})
	}
	sort.SliceStable(l, func(i, j int) bool { return l[i].Time.Before(l[j].Time) })
	return l, nil
}

func (s *Server) takeSnapshot(ds, name string) error {
	if _, err := s.Sys.Run("", "zfs", "snapshot", "-r", ds+"@"+name); err != nil {
		return fmt.Errorf("zfs snapshot %s: %v", name, err)
	}
	s.Log.Printf("snapshot: %s@%s", ds, name)
	return nil
}

func (s *Server) destroySnapshot(ds, name string) error {
	if snapKind(name) == "" || strings.ContainsAny(name, "@/ ") {
		return notFound("snapshot %s", name)
	}
	if _, err := s.Sys.Run("", "zfs", "destroy", "-r", ds+"@"+name); err != nil {
		return fmt.Errorf("zfs destroy %s: %v", name, err)
	}
	return nil
}

func (s *Server) snapZone() *time.Location {
	if l, err := time.LoadLocation(s.zoneFor(nil)); err == nil {
		return l
	}
	return time.UTC
}

var snapMu sync.Mutex // one tick at a time (the loop and a changed setting)

// snapTick takes the hourly and daily snapshots that are due and prunes old ones.
func (s *Server) snapTick(now time.Time) {
	snapMu.Lock()
	defer snapMu.Unlock()
	ds := s.dataDataset()
	if ds == "" {
		return
	}
	hourly, daily := s.snapKeep()
	l, err := s.snapshots(ds)
	if err != nil {
		s.Log.Printf("snapshot: %v", err)
		return
	}
	have := map[string]bool{}
	for _, x := range l {
		have[x.Name] = true
	}
	if h := snapHourly + now.UTC().Format("20060102T15Z"); hourly > 0 && !have[h] {
		if s.takeSnapshot(ds, h) == nil {
			l = append(l, Snapshot{Name: h, Kind: "hourly", Time: now})
		}
	}
	if d := snapDaily + now.In(s.snapZone()).Format(time.DateOnly); daily > 0 && !have[d] {
		// a consistent database dump in the same snapshot first
		if s.engineReady() {
			if _, err := s.Backup(); err != nil {
				s.Log.Printf("backup before the daily snapshot: %v", err)
			}
		}
		if s.takeSnapshot(ds, d) == nil {
			l = append(l, Snapshot{Name: d, Kind: "daily", Time: now})
		}
	}
	for kind, keep := range map[string]int{"hourly": hourly, "daily": daily} {
		var mine []Snapshot
		for _, x := range l {
			if x.Kind == kind {
				mine = append(mine, x)
			}
		}
		for i := 0; i < len(mine)-keep; i++ {
			if err := s.destroySnapshot(ds, mine[i].Name); err != nil {
				s.Log.Printf("snapshot: %v", err)
			}
		}
	}
}

// SnapLoop takes the snapshots (started by main on a real VM).
func (s *Server) SnapLoop() {
	for {
		s.snapTick(s.now())
		time.Sleep(time.Minute)
	}
}

// GET /v1/snapshots
func (s *Server) getSnapshots(r *http.Request) (any, error) {
	ds := s.dataDataset()
	hourly, daily := s.snapKeep()
	out := map[string]any{"dataset": ds, "hourly": hourly, "daily": daily, "snapshots": []Snapshot{}, "pull": s.pullOut()}
	if ds == "" {
		return out, nil
	}
	l, err := s.snapshots(ds)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 { // newest first
		l[i], l[j] = l[j], l[i]
	}
	if l != nil {
		out["snapshots"] = l
	}
	return out, nil
}

// POST /v1/snapshots: one now (kept until deleted)
func (s *Server) postSnapshot(r *http.Request) (any, error) {
	ds := s.dataDataset()
	if ds == "" {
		return nil, bad("/data is not a ZFS dataset (no data disk)")
	}
	n := snapManual + s.now().UTC().Format("20060102T150405Z")
	return map[string]any{"name": n}, s.takeSnapshot(ds, n)
}

// DELETE /v1/snapshots/{name}
func (s *Server) deleteSnapshot(r *http.Request) (any, error) {
	ds := s.dataDataset()
	if ds == "" {
		return nil, notFound("snapshot")
	}
	return map[string]any{}, s.destroySnapshot(ds, r.PathValue("name"))
}

// PUT /v1/snapshots/keep {"hourly": 24, "daily": 30}
func (s *Server) putSnapshotKeep(r *http.Request) (any, error) {
	var req struct {
		Hourly *int `json:"hourly"`
		Daily  *int `json:"daily"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Hourly != nil && (*req.Hourly < 0 || *req.Hourly > 168) {
		return nil, bad("hourly: 0 to 168")
	}
	if req.Daily != nil && (*req.Daily < 0 || *req.Daily > 400) {
		return nil, bad("daily: 0 to 400")
	}
	err := s.update(func(st *State) error {
		if req.Hourly != nil {
			st.SnapHourly = req.Hourly
		}
		if req.Daily != nil {
			st.SnapDaily = req.Daily
		}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	go s.snapTick(s.now()) // prune at once
	return s.getSnapshots(r)
}

// ---- the pull token ----

// pullSend runs zfs send and gives its output (tests replace it).
var pullSend = func(ctx context.Context, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, "zfs", append([]string{"send"}, args...)...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}, nil
}

// selfCert is keelAuth's own server certificate (not an imported one): the one the pull token pins.
func (s *Server) selfCert(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), chainFile))
	if err != nil {
		return nil, err
	}
	kb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), serverKeyFile))
	if err != nil {
		return nil, err
	}
	c, err := tls.X509KeyPair(cb, kb)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// webCert: the HTTPS port's certificate; the backup machine's server name gets the own one.
func (s *Server) webCert(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if h != nil && h.ServerName == BackupSNI {
		return s.selfCert(h)
	}
	return s.serverCert(h)
}

// pullCertHash: SHA-256 (lower-case hex) of the own certificate's leaf ("" without one).
func (s *Server) pullCertHash() string {
	cb, err := s.Sys.ReadFile(filepath.Join(s.tlsDir(), chainFile))
	if err != nil {
		return ""
	}
	b, _ := pem.Decode(cb)
	if b == nil {
		return ""
	}
	if _, err := x509.ParseCertificate(b.Bytes); err != nil {
		return ""
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

func (s *Server) pullOut() map[string]any {
	st := s.State().Pull
	allow := st.Allow
	if allow == nil {
		allow = []string{}
	}
	return map[string]any{
		"token_set": st.TokenHash != "", "token_at": st.TokenAt, "allow": allow,
		"token_stale": st.TokenHash != "" && st.TokenCert != s.pullCertHash(),
		"last_at": st.LastAt, "last_snap": st.LastSnap, "last_from": st.LastFrom,
	}
}

// pullAlert: a token exists but nobody fetched for two days.
func (s *Server) pullAlert() *Alert {
	st := s.State().Pull
	if st.TokenHash == "" {
		return nil
	}
	since := st.LastAt
	if since == "" {
		since = st.TokenAt
	}
	t, err := time.Parse(time.RFC3339, since)
	if err != nil || s.now().Sub(t) < pullStale {
		return nil
	}
	if st.LastAt == "" {
		return &Alert{"backup_never_pulled", "warning", "backup", "a backup pull token was made, but no backup machine has fetched a backup with it yet"}
	}
	return &Alert{"backup_not_pulled", "error", "backup", "the backup machine has not fetched a backup for two days (last: " + st.LastAt + ")"}
}

var pullHostRE = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)

// pullHost: the address the backup machine reaches this keelAuth at: the one asked for, else
// the first LAN address.
func (s *Server) pullHost(want string) (string, error) {
	if want != "" {
		if !pullHostRE.MatchString(want) {
			return "", bad("host: a name or an IPv4 address")
		}
		return want, nil
	}
	out, err := s.Sys.Run("", "ifconfig", "-a", "inet")
	if err == nil {
		if l := ParseAddresses(out); len(l) > 0 {
			return l[0], nil
		}
	}
	if d := s.State().Domain; d != "" {
		return d, nil
	}
	return "", coded(http.StatusConflict, "no_address", "this keelAuth has no LAN address yet: give the host the backup machine reaches it at")
}

// POST /v1/backup/pull-token {"host"?}: a new token (shown once), the old one stops working.
func (s *Server) postPullToken(r *http.Request) (any, error) {
	var req struct {
		Host string `json:"host"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			return nil, err
		}
	}
	cert := s.pullCertHash()
	if cert == "" {
		return nil, coded(http.StatusConflict, "no_certificate", "there is no server certificate yet")
	}
	host, err := s.pullHost(strings.TrimSpace(req.Host))
	if err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	sec := base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(sec))
	if err := s.update(func(st *State) error {
		st.Pull.TokenHash, st.Pull.TokenCert, st.Pull.TokenAt = hex.EncodeToString(sum[:]), cert, s.now().Format(time.RFC3339)
		return nil
	}, false); err != nil {
		return nil, err
	}
	port := "443"
	if _, p, err := net.SplitHostPort(s.State().HTTPSListen); err == nil && p != "" {
		port = p
	}
	return map[string]any{"token": pullTokenPrefix + "." + host + ":" + port + "." + sec + "." + cert, "pull": s.pullOut()}, nil
}

// DELETE /v1/backup/pull-token
func (s *Server) deletePullToken(r *http.Request) (any, error) {
	err := s.update(func(st *State) error { st.Pull.TokenHash, st.Pull.TokenCert, st.Pull.TokenAt = "", "", ""; return nil }, false)
	return map[string]any{"pull": s.pullOut()}, err
}

// PUT /v1/backup/pull-allow {"allow": ["192.0.2.0/24"]}
func (s *Server) putPullAllow(r *http.Request) (any, error) {
	var req struct {
		Allow []string `json:"allow"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	l, err := validPullAllow(req.Allow)
	if err != nil {
		return nil, err
	}
	err = s.update(func(st *State) error { st.Pull.Allow = l; return nil }, false)
	return map[string]any{"pull": s.pullOut()}, err
}

func validPullAllow(l []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, a := range l {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		ok := false
		if x, err := netip.ParseAddr(a); err == nil && x.Is4() {
			ok = true
		} else if p, err := netip.ParsePrefix(a); err == nil && p.Addr().Is4() {
			ok, a = true, p.Masked().String()
		}
		if !ok {
			return nil, bad("allow: %q is not an IPv4 address (or a.b.c.d/n block)", a)
		}
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	return out, nil
}

func pullAllowed(allow []string, remote string) bool {
	if len(allow) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, a := range allow {
		if p, err := netip.ParsePrefix(a); err == nil && p.Contains(ip) {
			return true
		}
		if x, err := netip.ParseAddr(a); err == nil && x == ip {
			return true
		}
	}
	return false
}

// ---- the backup machine's side ----

func (s *Server) pullAuthed(r *http.Request) bool {
	st := s.State().Pull
	if st.TokenHash == "" || !pullAllowed(st.Allow, r.RemoteAddr) {
		return false
	}
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	sum := sha256.Sum256([]byte(tok))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(st.TokenHash)) == 1
}

func pullJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// pullSnapshots: the snapshots a backup machine may take (daily and by hand), oldest first.
func (s *Server) pullSnapshots(ds string) ([]Snapshot, error) {
	l, err := s.snapshots(ds)
	if err != nil {
		return nil, err
	}
	var out []Snapshot
	for _, x := range l {
		if x.Kind == "daily" || x.Kind == "manual" {
			out = append(out, x)
		}
	}
	return out, nil
}

// pullName: the name the backup machine shows (the brand's product name, else keelAuth).
func (s *Server) pullName() string {
	if n := strings.TrimSpace(s.State().Brand.NameFor("")); n != "" {
		return n
	}
	return "keelAuth"
}

// BackupHandler serves /backup/v1/ (its own token; no login).
func (s *Server) BackupHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /backup/v1/info", func(w http.ResponseWriter, r *http.Request) {
		ds := s.dataDataset()
		l, err := s.pullSnapshots(ds)
		if ds == "" || err != nil {
			pullJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no data disk snapshots"})
			return
		}
		snaps := []map[string]any{}
		for _, x := range l {
			snaps = append(snaps, map[string]any{"name": x.Name, "kind": x.Kind, "time": x.Time})
		}
		pullJSON(w, 200, map[string]any{"format": 1, "kind": "keelauth", "name": s.pullName(), "host": s.State().Domain,
			"version": s.Version, "stream": "zfs", "dataset": ds, "snapshots": snaps})
	})
	mux.HandleFunc("GET /backup/v1/send", func(w http.ResponseWriter, r *http.Request) {
		ds := s.dataDataset()
		l, err := s.pullSnapshots(ds)
		if ds == "" || err != nil {
			pullJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "no data disk snapshots"})
			return
		}
		have := map[string]bool{}
		for _, x := range l {
			have[x.Name] = true
		}
		q := r.URL.Query()
		to, from := q.Get("to"), q.Get("from")
		if !have[to] || (from != "" && !have[from]) || from == to {
			pullJSON(w, http.StatusNotFound, map[string]string{"error": "unknown snapshot"})
			return
		}
		args := []string{"-R", "-c"}
		if from != "" {
			args = append(args, "-I", ds+"@"+from)
		}
		args = append(args, ds+"@"+to)
		out, wait, err := pullSend(r.Context(), args...)
		if err != nil {
			pullJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		w.Header().Set("Content-Type", "application/vnd.zfs-send")
		w.Header().Set("Cache-Control", "no-store")
		n, cerr := io.Copy(w, out)
		werr := wait()
		if cerr != nil || werr != nil {
			s.Log.Printf("backup pull: send %s→%s to %s stopped after %d bytes: %v %v", from, to, r.RemoteAddr, n, cerr, werr)
			return
		}
		s.Log.Printf("backup pull: sent %s→%s (%d bytes) to %s", from, to, n, r.RemoteAddr)
	})
	mux.HandleFunc("POST /backup/v1/done", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			To string `json:"to"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.To == "" {
			pullJSON(w, http.StatusBadRequest, map[string]string{"error": "to"})
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		s.update(func(st *State) error {
			st.Pull.LastAt, st.Pull.LastSnap, st.Pull.LastFrom = s.now().Format(time.RFC3339), req.To, host
			return nil
		}, false)
		pullJSON(w, 200, map[string]any{})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.pullAuthed(r) {
			pullJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad_token"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}
