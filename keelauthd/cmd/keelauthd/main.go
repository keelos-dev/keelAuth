// keelauthd is keelAuth's management daemon (docs/02-keelauthd.md is the specification):
//
//	keelauthd serve          the daemon (rc.d keelauthd)
//	keelauthd admin NAME     make NAME an administrator with a new password (prints it)
//	keelauthd status         the status, from the running daemon
//	keelauthd unlock         a locked master key: reads the recovery key or passphrase from stdin
//	keelauthd version
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	_ "time/tzdata" // zone names are checked here too (the image's zoneinfo may be trimmed)

	"keelauth/internal/auth"
	"keelauth/internal/engine"
	"keelauth/internal/sys"
)

var version = "dev"

const usage = `usage: keelauthd serve | admin NAME | status | unlock | version`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve()
	case "version":
		fmt.Println("keelauthd", version)
	case "status":
		out, err := local("GET", "/v1/status", nil)
		exit(out, err)
	case "unlock":
		exit(unlock())
	case "admin":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: keelauthd admin NAME")
			os.Exit(2)
		}
		exit(admin(os.Args[2]))
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

func serve() {
	lg := log.New(os.Stdout, "", log.LstdFlags)
	var srv *auth.Server
	eng := engine.NewKanidm(fmt.Sprintf("https://127.0.0.1:%d", auth.KanidmPort), "", func() (string, error) {
		return srv.AdminPassword()
	})
	srv, err := auth.NewServer(sys.Real{}, eng, auth.DataDir, version, lg)
	if err != nil {
		lg.Fatalf("keelauthd: %v", err)
	}
	eng.Recover = func() error {
		lg.Printf("idm_admin's password was refused: recovering a new one")
		return srv.RecoverAdmin()
	}
	srv.Heads = sys.Real{}
	srv.Real = true
	lg.Fatalf("keelauthd: %v", srv.Serve(auth.Socket))
}

// local calls the daemon's API on its Unix socket.
func local(method, path string, body any) (string, error) {
	c := &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", auth.Socket)
		}}}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = strings.NewReader(string(b))
	}
	req, _ := http.NewRequest(method, "http://keelauthd"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("keelauthd is not running? %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(b, &e)
		return "", fmt.Errorf("%s", e.Error)
	}
	return string(b), nil
}

// admin makes NAME an administrator: a new user, or an existing one put into keelauth-admins;
// either way with a new password, printed.
func admin(name string) (string, error) {
	if _, err := local("GET", "/v1/users/"+name, nil); err != nil {
		out, err := local("POST", "/v1/users", map[string]any{"name": name, "groups": []string{auth.AdminGroup}, "must_change": true})
		if err != nil {
			return "", err
		}
		var u struct{ Password string }
		json.Unmarshal([]byte(out), &u)
		return fmt.Sprintf("%s is an administrator now, password: %s (to be changed at the first login)", name, u.Password), nil
	}
	out, err := local("GET", "/v1/users/"+name, nil)
	if err != nil {
		return "", err
	}
	var u struct{ Groups []string }
	json.Unmarshal([]byte(out), &u)
	groups := append(u.Groups, auth.AdminGroup)
	if _, err := local("PATCH", "/v1/users/"+name, map[string]any{"groups": groups, "enabled": true}); err != nil {
		return "", err
	}
	out, err = local("POST", "/v1/users/"+name+"/password", map[string]any{"must_change": true})
	if err != nil {
		return "", err
	}
	var p struct{ Password string }
	json.Unmarshal([]byte(out), &p)
	return fmt.Sprintf("%s is an administrator, new password: %s (to be changed at the first login)", name, p.Password), nil
}

// unlock gives a locked keelauthd its recovery key (KAR1-…, from keel's web page) or the
// recovery passphrase, read from stdin (one line).
func unlock() (string, error) {
	fmt.Fprint(os.Stderr, "recovery key or passphrase: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	body := map[string]string{"passphrase": line}
	if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "KAR1") {
		body = map[string]string{"recovery_key": line}
	}
	if _, err := local("POST", "/unlock", body); err != nil {
		return "", err
	}
	return "unlocked", nil
}

func exit(out string, err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "keelauthd:", err)
		os.Exit(1)
	}
	fmt.Println(strings.TrimSpace(out))
}
