package auth

import (
	"strconv"
	"testing"
)

// The keelNAS sync (docs/02 section 3.5): keel asks with ?since= every few seconds, so every
// change a keelNAS shows must raise the revision; a display name too.
func TestSyncRevision(t *testing.T) {
	r := newRig(t)
	r.ok("POST", "/v1/users", map[string]any{"name": "alice", "display_name": "Alice", "password": "Keel-Auth-2026"})
	rev := r.s.State().Revision
	out := r.ok("GET", "/v1/sync/accounts?since="+strconv.FormatInt(rev, 10), nil)
	if out["unchanged"] != true {
		t.Fatalf("unchanged: %v", out)
	}
	r.ok("PATCH", "/v1/users/alice", map[string]any{"display_name": "Alice Wang"})
	if r.s.State().Revision <= rev {
		t.Fatal("a new display name did not raise the revision")
	}
	out = r.ok("GET", "/v1/sync/accounts?since="+strconv.FormatInt(rev, 10), nil)
	if out["unchanged"] != nil || out["users"].([]any)[0].(map[string]any)["display_name"] != "Alice Wang" {
		t.Errorf("after the change: %v", out)
	}
	rev = r.s.State().Revision
	r.ok("PATCH", "/v1/users/alice", map[string]any{"mail": "alice@office.lan"})
	if r.s.State().Revision != rev {
		t.Error("a mail address (not synced) raised the revision")
	}
}
