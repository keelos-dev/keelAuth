package auth

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSupportBundle(t *testing.T) {
	r := newRig(t)
	r.sy.Files["/var/log/keelauthd.log"] = []byte("keelauthd: key kap_abcdefghijkl used\nAuthorization: Bearer kat_zzzzzzzzzzzz\n")
	r.sy.Files["/var/log/messages"] = []byte("Oct 29 09:00:00 keelauth kanidmd[123]: ERROR No such sessionid exists\nOct 29 09:00:01 keelauth sshd[1]: hello\n")
	old := r.sy.Handle
	r.sy.Handle = func(line, stdin string) (string, error, bool) {
		if strings.HasPrefix(line, "ps ") {
			return "PID COMMAND\n1 /usr/local/libexec/kanidmd server\n", nil, true
		}
		return old(line, stdin)
	}
	req := httptest.NewRequest("GET", "/v1/support-bundle", nil)
	req.Header.Set("Authorization", "Bearer "+r.key)
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Disposition"), `attachment; filename="keelauth-support-`) {
		t.Fatalf("%d %s %s", rec.Code, rec.Header().Get("Content-Disposition"), rec.Body.String())
	}
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		got[h.Name[strings.Index(h.Name, "/")+1:]] = string(b)
	}
	for _, n := range []string{"README.txt", "status.json", "settings.json", "files/keelauthd.log", "files/messages", "files/kanidmd-from-messages.log", "system/ps_axww_-o_pid,ppid,user,start,time,command.txt"} {
		if _, ok := got[n]; !ok {
			t.Errorf("no %s in the bundle (%v)", n, bundleNames(got))
		}
	}
	if l := got["files/keelauthd.log"]; strings.Contains(l, "kap_abcdefghijkl") || strings.Contains(l, "kat_zzzz") || !strings.Contains(l, "kap_…") || !strings.Contains(l, "Bearer kat_…") {
		t.Errorf("secrets not blanked: %q", l)
	}
	if k := got["files/kanidmd-from-messages.log"]; !strings.Contains(k, "No such sessionid") || strings.Contains(k, "sshd") {
		t.Errorf("kanidmd filter: %q", k)
	}
	if !strings.Contains(got["system/ps_axww_-o_pid,ppid,user,start,time,command.txt"], "kanidmd server") {
		t.Errorf("ps: %q", got["system/ps_axww_-o_pid,ppid,user,start,time,command.txt"])
	}
	if !strings.Contains(got["README.txt"], "Not collected:\n  /var/log/radius.log") {
		t.Errorf("README should list the missing files: %q", got["README.txt"])
	}
	if !strings.Contains(got["status.json"], `"version"`) {
		t.Errorf("status.json: %q", got["status.json"])
	}
	// an API key, even an administrator's, gets no logs: that is for a person in the web
	ak := r.ok("POST", "/v1/api/keys", map[string]any{"name": "k", "scope": "admin"})["key"].(string)
	if code, _, _ := r.call("GET", "/v1/support-bundle", "Bearer "+ak, nil); code != 403 {
		t.Errorf("API key: %d, want 403", code)
	}
}

func bundleNames(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
