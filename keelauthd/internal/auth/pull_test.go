package auth

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeZFS answers the zfs commands pull.go runs, over a set of snapshots of "kadata".
type fakeZFS struct {
	mu    sync.Mutex
	snaps map[string]int64 // name → creation
	clock func() time.Time
}

func (z *fakeZFS) handle(line, _ string) (string, error, bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	switch {
	case line == "zfs list -H -o name /data":
		return "kadata\n", nil, true
	case strings.HasPrefix(line, "zfs list -H -p -t snapshot"):
		var names []string
		for n := range z.snaps {
			names = append(names, n)
		}
		sort.Strings(names)
		var b strings.Builder
		for _, n := range names {
			fmt.Fprintf(&b, "kadata@%s\t%d\t4096\n", n, z.snaps[n])
		}
		b.WriteString("kadata@someone-elses\t1\t1\n")
		return b.String(), nil, true
	case strings.HasPrefix(line, "zfs snapshot -r kadata@"):
		z.snaps[strings.TrimPrefix(line, "zfs snapshot -r kadata@")] = z.clock().Unix()
		return "", nil, true
	case strings.HasPrefix(line, "zfs destroy -r kadata@"):
		delete(z.snaps, strings.TrimPrefix(line, "zfs destroy -r kadata@"))
		return "", nil, true
	}
	return "", nil, false
}

func TestSnapshotSchedule(t *testing.T) {
	r := newRig(t)
	now := time.Date(2026, 11, 17, 0, 30, 0, 0, time.UTC)
	z := &fakeZFS{snaps: map[string]int64{}, clock: func() time.Time { return now }}
	old := r.sy.Handle
	r.sy.Handle = func(line, stdin string) (string, error, bool) {
		if o, e, ok := z.handle(line, stdin); ok {
			return o, e, ok
		}
		return old(line, stdin)
	}
	r.ok("PUT", "/v1/snapshots/keep", map[string]any{"hourly": 3, "daily": 2})
	time.Sleep(50 * time.Millisecond) // the prune that PUT starts
	for i := 0; i < 80; i++ { // 80 hours, a tick every hour
		r.s.snapTick(now)
		now = now.Add(time.Hour)
	}
	var h, d []string
	for n := range z.snaps {
		switch snapKind(n) {
		case "hourly":
			h = append(h, n)
		case "daily":
			d = append(d, n)
		}
	}
	sort.Strings(h)
	sort.Strings(d)
	if len(h) != 3 || h[2] != "keel-h-20261120T07Z" {
		t.Errorf("hourly %v", h)
	}
	if len(d) != 2 || d[1] != "keel-d-2026-11-20" {
		t.Errorf("daily %v", d)
	}
	// by hand: kept by the schedule, listed newest first, deleted by name
	m := r.ok("POST", "/v1/snapshots", nil)["name"].(string)
	r.s.snapTick(now)
	l := r.ok("GET", "/v1/snapshots", nil)
	if l["dataset"] != "kadata" || len(l["snapshots"].([]any)) != 6 {
		t.Fatalf("list %v", l)
	}
	r.ok("DELETE", "/v1/snapshots/"+m, nil)
	if _, ok := z.snaps[m]; ok {
		t.Error("manual not deleted")
	}
	if c, _, _ := r.call("DELETE", "/v1/snapshots/someone-elses", "", nil); c != 404 {
		t.Errorf("foreign snapshot: %d", c)
	}
	// 0 = none, the old ones go
	r.ok("PUT", "/v1/snapshots/keep", map[string]any{"hourly": 0})
	time.Sleep(50 * time.Millisecond)
	for n := range z.snaps {
		if snapKind(n) == "hourly" {
			t.Errorf("hourly left: %s", n)
		}
	}
}

func TestBackupPull(t *testing.T) {
	r := newRig(t)
	now := time.Date(2026, 11, 17, 3, 0, 0, 0, time.UTC)
	r.s.Now = func() time.Time { return now }
	z := &fakeZFS{snaps: map[string]int64{"keel-d-2026-11-16": 1, "keel-d-2026-11-17": 4, "keel-h-20261117T02Z": 3, "keel-m-20261117T010000Z": 2}, clock: func() time.Time { return now }}
	old := r.sy.Handle
	r.sy.Handle = func(line, stdin string) (string, error, bool) {
		if o, e, ok := z.handle(line, stdin); ok {
			return o, e, ok
		}
		return old(line, stdin)
	}
	var sent []string
	pullSend = func(_ context.Context, args ...string) (io.ReadCloser, func() error, error) {
		sent = args
		return io.NopCloser(strings.NewReader("STREAM")), func() error { return nil }, nil
	}
	if _, err := r.s.EnsureTLS("auth.example.com", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	h := r.s.BackupHandler()
	do := func(method, path, tok, remote, body string) (int, string) {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = remote + ":40000"
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, w.Body.String()
	}
	if c, _ := do("GET", "/backup/v1/info", "x", "192.0.2.50", ""); c != 401 {
		t.Errorf("no token made: %d", c)
	}
	full := r.ok("POST", "/v1/backup/pull-token", nil)["token"].(string)
	parts := strings.Split(full, ".")
	if parts[0] != "kbk1" || !strings.HasPrefix(full, "kbk1.192.0.2.10:443.") || len(parts[len(parts)-1]) != 64 {
		t.Fatalf("token %s", full)
	}
	sec := strings.Split(strings.SplitN(full, ":", 2)[1], ".")[1]
	if c, _ := do("GET", "/backup/v1/info", "wrong", "192.0.2.50", ""); c != 401 {
		t.Errorf("wrong token: %d", c)
	}
	c, body := do("GET", "/backup/v1/info", sec, "192.0.2.50", "")
	var info struct {
		Kind      string `json:"kind"`
		Snapshots []struct{ Name string } `json:"snapshots"`
	}
	json.Unmarshal([]byte(body), &info)
	if c != 200 || info.Kind != "keelauth" || len(info.Snapshots) != 3 || info.Snapshots[2].Name != "keel-d-2026-11-17" {
		t.Errorf("info %d %s", c, body) // daily and by hand, not hourly
	}
	if c, b := do("GET", "/backup/v1/send?to=keel-d-2026-11-17", sec, "192.0.2.50", ""); c != 200 || b != "STREAM" || strings.Join(sent, " ") != "-R -c kadata@keel-d-2026-11-17" {
		t.Errorf("full send %d %q %v", c, b, sent)
	}
	if c, _ := do("GET", "/backup/v1/send?from=keel-d-2026-11-16&to=keel-d-2026-11-17", sec, "192.0.2.50", ""); c != 200 || strings.Join(sent, " ") != "-R -c -I kadata@keel-d-2026-11-16 kadata@keel-d-2026-11-17" {
		t.Errorf("incremental %v", sent)
	}
	for _, q := range []string{"to=keel-h-20261117T02Z", "to=nope", "to=keel-d-2026-11-17;rm", "from=x&to=keel-d-2026-11-17"} {
		if c, _ := do("GET", "/backup/v1/send?"+q, sec, "192.0.2.50", ""); c != 404 {
			t.Errorf("%s: %d", q, c)
		}
	}
	// read-only: no other calls
	if c, _ := do("DELETE", "/backup/v1/info", sec, "192.0.2.50", ""); c != 405 {
		t.Errorf("delete: %d", c)
	}
	// no pull for two days: alert; a done clears it
	now = now.Add(49 * time.Hour)
	if a := r.s.pullAlert(); a == nil || a.Code != "backup_never_pulled" {
		t.Errorf("alert %+v", a)
	}
	if c, _ := do("POST", "/backup/v1/done", sec, "192.0.2.50", `{"to":"keel-d-2026-11-17"}`); c != 200 {
		t.Error(c)
	}
	if a := r.s.pullAlert(); a != nil {
		t.Errorf("after done %+v", a)
	}
	if p := r.s.State().Pull; p.LastSnap != "keel-d-2026-11-17" || p.LastFrom != "192.0.2.50" {
		t.Errorf("state %+v", p)
	}
	now = now.Add(49 * time.Hour)
	if a := r.s.pullAlert(); a == nil || a.Code != "backup_not_pulled" {
		t.Errorf("stale %+v", a)
	}
	// allow list
	r.ok("PUT", "/v1/backup/pull-allow", map[string]any{"allow": []string{"198.51.100.0/24"}})
	if c, _ := do("GET", "/backup/v1/info", sec, "192.0.2.50", ""); c != 401 {
		t.Errorf("outside the allow list: %d", c)
	}
	// the backup name gets keelAuth's own certificate
	if c, err := r.s.webCert(&tls.ClientHelloInfo{ServerName: BackupSNI}); err != nil || c == nil {
		t.Errorf("sni cert %v", err)
	} else if sum := sha256.Sum256(c.Certificate[0]); hex.EncodeToString(sum[:]) != parts[len(parts)-1] {
		t.Errorf("the backup name's certificate is not the pinned one")
	}
	// revoked
	r.ok("DELETE", "/v1/backup/pull-token", nil)
	if c, _ := do("GET", "/backup/v1/info", sec, "198.51.100.7", ""); c != 401 {
		t.Errorf("revoked: %d", c)
	}
	_ = http.StatusOK
}
