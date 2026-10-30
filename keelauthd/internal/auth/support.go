package auth

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
)

// Support bundle (GET /v1/support-bundle, administrators in the web): one click makes a tar.gz
// with what a fault needs: keelauthd's log, the system log (kanidmd logs through syslog, the
// port's rc.d runs it with daemon -T kanidmd), FreeRADIUS's log, status and settings as the API
// shows them, services, processes, sockets, disk, time and uptime. Asked for 2026-10-29: an
// instance on a host nobody else reaches answered "kanidm: 500 invalidstate", and only
// kanidmd's log says which state. No secrets go in: the state file is not included, and tokens
// (kat_/kas_/kap_), Bearer headers and password-like JSON fields are blanked in every text.

const supportLogMax = 4 << 20 // the tail of each log file

var supportFiles = []string{
	"/var/log/keelauthd.log", "/var/log/messages", "/var/log/radius.log",
	"/usr/local/etc/kanidm/config.toml", "/usr/local/etc/kanidm/keelos-fork.version",
}

var supportCommands = [][]string{
	{"date", "-u"}, {"uptime"}, {"sysctl", "kern.boottime", "kern.osrelease", "hw.physmem"},
	{"service", "kanidmd", "status"}, {"service", "radiusd", "status"},
	{"ps", "axww", "-o", "pid,ppid,user,start,time,command"}, {"sockstat", "-4", "-6", "-l"},
	{"df", "-h"}, {"swapinfo"}, {"ifconfig", "-a"}, {"dmesg"},
}

var supportSecrets = []*regexp.Regexp{
	regexp.MustCompile(`\bka[tsp]_[A-Za-z0-9_-]{6,}`),
	regexp.MustCompile(`(?i)bearer [A-Za-z0-9._~+/=-]{6,}`),
	regexp.MustCompile(`(?i)"(password|secret|client_secret|key|token|recovery_key|nt|value)"\s*:\s*"[^"]*"`),
	regexp.MustCompile(`(?i)(password|secret)=\S+`),
}

// redact blanks what looks like a secret; the shape stays so the log still reads.
func redact(b []byte) []byte {
	for i, re := range supportSecrets {
		switch i {
		case 0:
			b = re.ReplaceAllFunc(b, func(m []byte) []byte { return append(m[:4:4], []byte("…")...) })
		case 1:
			b = re.ReplaceAll(b, []byte("Bearer …"))
		case 2:
			b = re.ReplaceAll(b, []byte(`"$1": "…"`))
		default:
			b = re.ReplaceAll(b, []byte("$1=…"))
		}
	}
	return b
}

func (s *Server) getSupportBundle(w http.ResponseWriter, r *http.Request) {
	now := s.now().UTC()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	top := "keelauth-support-" + now.Format("20060102T150405Z")
	add := func(name string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: top + "/" + name, Mode: 0600, Size: int64(len(b)), ModTime: now})
		tw.Write(b)
	}
	var notes []string
	if st, err := s.getStatus(r); err == nil {
		b, _ := json.MarshalIndent(st, "", "  ")
		add("status.json", redact(b))
	} else {
		notes = append(notes, "status: "+err.Error())
	}
	b, _ := json.MarshalIndent(s.settingsOut(r), "", "  ")
	add("settings.json", redact(b))
	for _, f := range supportFiles {
		b, err := s.Sys.ReadFile(f)
		if err != nil {
			notes = append(notes, f+": "+err.Error())
			continue
		}
		if len(b) > supportLogMax {
			b = b[len(b)-supportLogMax:]
		}
		add("files/"+filepath.Base(f), redact(b))
	}
	// kanidmd's lines of the system log on their own: what "invalidstate" and friends mean
	if b, err := s.Sys.ReadFile("/var/log/messages"); err == nil {
		var k []string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.Contains(l, "kanidmd") {
				k = append(k, l)
			}
		}
		add("files/kanidmd-from-messages.log", redact([]byte(strings.Join(k, "\n"))))
	}
	for _, c := range supportCommands {
		out, err := s.Sys.Run("", c[0], c[1:]...)
		if err != nil {
			out += "\n[" + err.Error() + "]"
		}
		add("system/"+strings.Join(c, "_")+".txt", redact([]byte(out)))
	}
	readme := "keelAuth support bundle, " + now.Format("2006-01-02 15:04:05") + " UTC, keelauthd " + s.versionString() +
		", host " + s.hostname() + "\n\nstatus.json, settings.json: what the API answers; files/: logs and configuration" +
		" (kanidmd logs through syslog: files/messages, filtered in kanidmd-from-messages.log); system/: commands.\n" +
		"Secrets are blanked (tokens, Bearer headers, password-like fields); the state file is not included.\n"
	if len(notes) > 0 {
		readme += "\nNot collected:\n  " + strings.Join(notes, "\n  ") + "\n"
	}
	add("README.txt", []byte(readme))
	tw.Close()
	gz.Close()
	s.Log.Printf("support bundle made (%d bytes)", buf.Len())
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+top+`.tar.gz"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}
