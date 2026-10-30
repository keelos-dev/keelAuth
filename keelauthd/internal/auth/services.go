package auth

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/secret"
)

// Kanidm and FreeRADIUS: their configuration is generated from the state at every start and
// after every change; keelauthd starts them itself (the image leaves them disabled in rc.conf).

const (
	KanidmConf    = "/usr/local/etc/kanidm/config.toml"
	KanidmBin     = "/usr/local/libexec/kanidmd"
	RaddbDir      = "/usr/local/etc/raddb"
	RadClients    = RaddbDir + "/clients.conf"
	RadAuthorize  = RaddbDir + "/mods-config/files/authorize"
	generatedMark = "# Written by keelauthd from " + DataDir + "/state.json. Changes here are overwritten.\n"
)

func (s *Server) kanidmDir() string { return filepath.Join(s.Data, "kanidm") }

// originURL is an origin for a host (a domain or an IPv4 address).
func originURL(host string) string { return fmt.Sprintf("https://%s:%d", host, KanidmPort) }

// OriginInfo says how Kanidm's origin is made: mode "ip" (the host is the fixed LAN address, lan)
// or "domain". want is what the seed asked for; fallback says why "ip" was refused (""
// otherwise). Every origin, issuer and discovery address comes from here (docs/02 section 7.14).
func (s *Server) OriginInfo() (mode, lan, want, fallback string) {
	s.hmu.Lock()
	sd := s.seed
	s.hmu.Unlock()
	want = "domain"
	if sd != nil && sd.Origin == "ip" {
		want = "ip"
	}
	if want == "domain" {
		return "domain", "", want, ""
	}
	if sd.Lan != nil && sd.Lan.Mode == "static" {
		if ip, _, err := net.ParseCIDR(sd.Lan.Address); err == nil && ip.To4() != nil {
			return "ip", ip.String(), want, ""
		}
	}
	return "domain", "", want, "IP origin needs a fixed LAN address: this keelAuth gets its address by DHCP, so the origin stays the domain name"
}

// Origin is Kanidm's origin: where browsers reach its login page (SSO) and the base of every
// OIDC issuer.
func (s *Server) Origin() string {
	if mode, lan, _, _ := s.OriginInfo(); mode == "ip" {
		return originURL(lan)
	}
	return originURL(s.State().Domain)
}

// BaseDN is Kanidm's LDAP base DN for a domain: dc=auth,dc=office,dc=lan.
func BaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	for i, p := range parts {
		parts[i] = "dc=" + p
	}
	return strings.Join(parts, ",")
}

// KanidmConfig is Kanidm's config.toml for the state; zfs: the database is on ZFS (Kanidm then
// uses 64 KiB pages to match the record size; the image makes kadata with recordsize=64K).
func (s *Server) KanidmConfig(st *State, zfs bool) string {
	// the password rules (docs/02 §3.14; our fork's keel_password_* keys)
	minLen, strength := st.PasswordPolicy()
	fsType := ""
	if zfs {
		fsType = "db_fs_type = \"zfs\"\n"
	}
	return generatedMark + fmt.Sprintf(`version = "2"
bindaddress = "0.0.0.0:%d"
ldapbindaddress = "0.0.0.0:%d"
db_path = %q
tls_chain = %q
tls_key = %q
domain = %q
origin = %q
keel_password_min_length = %d
keel_password_min_score = %d
`, KanidmPort, st.LDAPPort, filepath.Join(s.kanidmDir(), "kanidm.db"), filepath.Join(s.tlsDir(), useServerChain),
		filepath.Join(s.tlsDir(), useServerKey), st.Domain, s.Origin(), minLen, passwordScores[strength]) + fsType
}

// FSType is the file system type a path is on, from `mount -p` (the longest mount point that
// is a prefix of the path); "" when unknown.
func (s *Server) FSType(path string) string {
	out, err := s.Sys.Run("", "mount", "-p")
	if err != nil {
		return ""
	}
	return ParseMountType(out, path)
}

// ParseMountType reads `mount -p` (fstab lines: device, mount point, type, ...).
func ParseMountType(out, path string) string {
	best, typ := "", ""
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		mp := f[1]
		under := path == mp || mp == "/" || strings.HasPrefix(path, strings.TrimSuffix(mp, "/")+"/")
		if under && len(mp) > len(best) {
			best, typ = mp, f[2]
		}
	}
	return typ
}

// tlsPerms: the directory is open (the keys guard themselves), the server key is for kanidmd,
// the RADIUS key for freeradius, the CA key for root only.
func (s *Server) tlsPerms() {
	d := s.tlsDir()
	for _, c := range [][]string{
		{"chown", "root:wheel", d}, {"chmod", "0755", d},
		{"chown", "root:kanidmd", filepath.Join(d, serverKeyFile)}, {"chmod", "0640", filepath.Join(d, serverKeyFile)},
		{"chown", "root:freeradius", filepath.Join(d, radiusKeyFile)}, {"chmod", "0640", filepath.Join(d, radiusKeyFile)},
		{"chmod", "0600", filepath.Join(d, caKeyFile)},
		{"chown", "root:kanidmd", filepath.Join(d, useServerKey)}, {"chmod", "0640", filepath.Join(d, useServerKey)},
		{"chown", "root:freeradius", filepath.Join(d, useRadiusKey)}, {"chmod", "0640", filepath.Join(d, useRadiusKey)},
	} {
		if _, err := s.Sys.Run("", c[0], c[1:]...); err != nil {
			s.Log.Printf("%v", err)
		}
	}
}

// running reports whether an rc service runs.
func (s *Server) running(svc string) bool {
	_, err := s.Sys.Run("", "service", svc, "onestatus")
	return err == nil
}

// writeIfChanged writes a file only when its content differs; it reports whether it wrote.
func (s *Server) writeIfChanged(path, content string, perm uint32) (bool, error) {
	if old, err := s.Sys.ReadFile(path); err == nil && string(old) == content {
		return false, nil
	}
	return true, s.Sys.WriteFile(path, []byte(content), osMode(perm))
}

// StartKanidm prepares the directories and the configuration and makes sure kanidmd runs
// with it (restarted when the configuration or the certificate changed).
func (s *Server) StartKanidm(certChanged bool) error {
	st := s.State()
	run := func(name string, args ...string) {
		if _, err := s.Sys.Run("", name, args...); err != nil {
			s.Log.Printf("%v", err)
		}
	}
	run("install", "-d", "-o", "kanidmd", "-g", "kanidmd", "-m", "0700", s.kanidmDir())
	s.tlsPerms()
	if st.LDAPPort < 1024 {
		// Kanidm runs as kanidmd: let it bind LDAPS on 636 (an appliance VM with no other users)
		run("sysctl", "net.inet.ip.portrange.reservedhigh=0")
	}
	changed, err := s.writeIfChanged(KanidmConf, s.KanidmConfig(st, s.FSType(s.kanidmDir()) == "zfs"), 0o644)
	if err != nil {
		return err
	}
	run("chown", "root:kanidmd", KanidmConf)
	run("chmod", "0640", KanidmConf)
	switch {
	case !s.running("kanidmd"):
		_, err = s.Sys.Run("", "service", "kanidmd", "onestart")
	case changed || certChanged:
		_, err = s.Sys.Run("", "service", "kanidmd", "onerestart")
	}
	return err
}

var newPasswordRE = regexp.MustCompile(`new_password: "([^"]+)"`)

// RecoverAdmin gives idm_admin a new password through kanidmd's local admin socket and keeps
// it (sealed) in the state.
func (s *Server) RecoverAdmin() error {
	out, err := s.Sys.Run("", KanidmBin, "recover-account", "-c", KanidmConf, "idm_admin")
	if err != nil {
		return err
	}
	m := newPasswordRE.FindStringSubmatch(out)
	if m == nil {
		return errors.New("kanidmd recover-account printed no password")
	}
	return s.update(func(st *State) error {
		st.Admin = s.box.Seal(m[1])
		return nil
	}, false)
}

// adminPassword is idm_admin's password for the engine.
func (s *Server) adminPassword() (string, error) {
	if s.Locked() {
		return "", errLocked
	}
	st := s.State()
	if st.Admin == "" {
		return "", errors.New("no idm_admin password yet")
	}
	return s.box.Open(st.Admin)
}

// BringUp starts Kanidm, logs in as idm_admin (recovering its password when needed),
// prepares Kanidm, the LDAP bind account and FreeRADIUS. Errors are kept for the status.
// Only when both services are seen up (process and port, CheckServices) is it "ready".
func (s *Server) BringUp() error {
	err := s.bringUp()
	s.hmu.Lock()
	s.engineErr = err
	s.hmu.Unlock()
	if err != nil {
		s.Log.Printf("bring-up: %v", err)
	}
	svc := s.waitServices()
	switch {
	case err == nil && svc["kanidmd"] == nil && svc["radiusd"] == nil:
		s.Log.Printf("bring-up: Kanidm and FreeRADIUS ready")
	default:
		for _, n := range []string{"kanidmd", "radiusd"} {
			if svc[n] != nil {
				s.Log.Printf("bring-up: %s is NOT up: %v", n, svc[n])
			} else {
				s.Log.Printf("bring-up: %s up", n)
			}
		}
	}
	if err == nil {
		for _, n := range []string{"kanidmd", "radiusd"} {
			if svc[n] != nil {
				return fmt.Errorf("%s: %v", n, svc[n])
			}
		}
	}
	return err
}

func (s *Server) bringUp() error {
	if s.Real {
		ch, err := s.EnsureTLS(s.State().Domain, s.internalIP())
		if err != nil {
			return fmt.Errorf("tls: %v", err)
		}
		if ch.Radius && s.running("radiusd") {
			s.Sys.Run("", "service", "radiusd", "onestop")
		}
		if err := s.StartKanidm(ch.Server); err != nil {
			return fmt.Errorf("kanidmd: %v", err)
		}
	}
	// Kanidm takes a few seconds to come up after a (re)start
	var err error
	for i := 0; i < s.waitTries(); i++ {
		if s.State().Admin == "" {
			if err = s.RecoverAdmin(); err != nil {
				s.sleep(2 * time.Second)
				continue
			}
		}
		if err = s.Eng.Ready(); err == nil {
			break
		}
		s.sleep(2 * time.Second)
	}
	if err != nil {
		return err
	}
	if err := s.reindexOnce(); err != nil {
		return fmt.Errorf("reindex: %v", err)
	}
	if err := s.Eng.Prepare(AdminGroup); err != nil {
		return fmt.Errorf("prepare: %v", err)
	}
	if err := s.ensureBindAccount(false); err != nil {
		return fmt.Errorf("ldap bind account: %v", err)
	}
	return s.ApplyRadius()
}

// KanidmVersionFile names the forked kanidmd's commit (tools/image/build.sh); the port's has none.
const KanidmVersionFile = "/usr/local/etc/kanidm/keelos-fork.version"

func (s *Server) kanidmdVersion() string {
	if b, err := s.Sys.ReadFile(KanidmVersionFile); err == nil && strings.TrimSpace(string(b)) != "" {
		return strings.TrimSpace(string(b))
	}
	return "port"
}

// reindexOnce: Kanidm 1.11.0's startup reindex runs before its domain migration adds indexed
// attributes (UserAuthTokenSession, OAuth2RsScopeMap, ...), so a fresh database lacks those
// indexes for good: "index ... was not found. YOU MUST REINDEX YOUR DATABASE" in the log, and
// every search on them is refused as "fully unindexed" (ResourceLimit) - the Kanidm UI's apps
// page after login answered 500 "Backend" on two production instances and on a fresh test
// one (2026-10-29). `kanidmd database reindex` (offline) puts the indexes in. So once per
// kanidmd build (marker in the kanidm directory), after Kanidm came up the first time: stop
// it, reindex as the kanidmd user, start it again.
func (s *Server) reindexOnce() error {
	ver := s.kanidmdVersion()
	mark := filepath.Join(s.kanidmDir(), ".reindexed")
	if b, err := s.Sys.ReadFile(mark); err == nil && strings.TrimSpace(string(b)) == ver {
		return nil
	}
	s.Log.Printf("kanidm: reindexing the database once for kanidmd %s", ver)
	if _, err := s.Sys.Run("", "service", "kanidmd", "onestop"); err != nil {
		return err
	}
	_, err := s.Sys.Run("", "su", "-m", "kanidmd", "-c", KanidmBin+" database reindex -c "+KanidmConf)
	if _, err2 := s.Sys.Run("", "service", "kanidmd", "onestart"); err == nil {
		err = err2
	}
	if err != nil {
		return err
	}
	for i := 0; i < s.waitTries(); i++ {
		if err = s.Eng.Ready(); err == nil {
			break
		}
		s.sleep(2 * time.Second)
	}
	if err != nil {
		return err
	}
	s.Log.Printf("kanidm: reindexed")
	return s.Sys.WriteFile(mark, []byte(ver+"\n"), 0o644)
}

func (s *Server) waitTries() int {
	if s.Real {
		return 45
	}
	return 2
}

func (s *Server) sleep(d time.Duration) {
	if s.Real {
		time.Sleep(d)
	}
}

// ensureBindAccount makes the read-only LDAP bind account for devices and gives it its
// password (a new one with reset).
func (s *Server) ensureBindAccount(reset bool) error {
	st := s.State()
	pw, _ := s.box.Open(st.BindPW)
	if _, err := s.Eng.User(BindAccount); errors.Is(err, engine.ErrNotFound) {
		if _, err := s.Eng.CreateUser(BindAccount, "LDAP bind account (devices)", ""); err != nil {
			return err
		}
		pw = ""
	} else if err != nil {
		return err
	}
	if pw != "" && !reset {
		if ok, err := s.Eng.CheckPassword(BindAccount, pw); err == nil && ok {
			return nil
		}
	}
	pw = secret.Password()
	if err := s.Eng.SetPassword(BindAccount, pw); err != nil {
		return err
	}
	return s.update(func(st *State) error { st.BindPW = s.box.Seal(pw); return nil }, false)
}

// ---- FreeRADIUS ----

// RadiusFiles are clients.conf and the files module's authorize for the state and the engine's
// users: one NT-Password line per enabled user with an NT hash (and in the RADIUS group when
// one is set).
func (s *Server) RadiusFiles(st *State, users []engine.User) (clients, authorize string, err error) {
	var c strings.Builder
	c.WriteString(generatedMark)
	local, err := s.box.Open(st.Radius.Local)
	if err != nil {
		return "", "", err
	}
	fmt.Fprintf(&c, "\n# keelauthd's own self-test\nclient localhost {\n\tipaddr = 127.0.0.1\n\tsecret = \"%s\"\n}\n", local)
	for _, rc := range st.Radius.Clients {
		sec, err := s.box.Open(rc.Secret)
		if err != nil {
			return "", "", fmt.Errorf("client %s: %v", rc.Name, err)
		}
		fmt.Fprintf(&c, "\nclient %s {\n\tipaddr = %s\n\tsecret = \"%s\"\n\tshortname = %s\n}\n", rc.Name, rc.Address, sec, rc.Name)
	}
	var a strings.Builder
	a.WriteString(generatedMark)
	names := []string{}
	for _, u := range users {
		if !u.Enabled || u.Name == BindAccount {
			continue
		}
		if st.Radius.Group != "" && !contains(u.Groups, st.Radius.Group) {
			continue
		}
		d := st.Users[u.Name]
		if d == nil || d.NT == "" {
			continue
		}
		names = append(names, u.Name)
	}
	sort.Strings(names)
	for _, n := range names {
		nt, err := s.box.Open(st.Users[n].NT)
		if err != nil {
			return "", "", fmt.Errorf("user %s: %v", n, err)
		}
		fmt.Fprintf(&a, "%s\tNT-Password := 0x%s\n", n, strings.ToUpper(nt))
	}
	return c.String(), a.String(), nil
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// ApplyRadius writes FreeRADIUS's files and restarts it when they changed (or starts it when
// it is not running).
func (s *Server) ApplyRadius() error {
	s.radMu.Lock()
	defer s.radMu.Unlock()
	if s.State().Radius.Local == "" {
		if err := s.update(func(st *State) error { st.Radius.Local = s.box.Seal(secret.Random(12)); return nil }, false); err != nil {
			return err
		}
	}
	users, err := s.Eng.Users()
	if err != nil {
		return err
	}
	clients, auth, err := s.RadiusFiles(s.State(), users)
	if err != nil {
		return err
	}
	c1, err := s.writeIfChanged(RadClients, clients, 0o640)
	if err != nil {
		return err
	}
	c2, err := s.writeIfChanged(RadAuthorize, auth, 0o640)
	if err != nil {
		return err
	}
	if c1 || c2 {
		s.Sys.Run("", "chown", "root:freeradius", RadClients, RadAuthorize)
	}
	switch {
	case !s.running("radiusd"):
		_, err = s.Sys.Run("", "service", "radiusd", "onestart")
	case c1 || c2:
		_, err = s.Sys.Run("", "service", "radiusd", "onerestart")
	}
	return err
}

// radiusLater regenerates FreeRADIUS's files after an account change, logging a failure (the
// change itself has happened; the alert says RADIUS is behind).
func (s *Server) radiusLater() {
	if err := s.ApplyRadius(); err != nil {
		s.Log.Printf("radius: %v", err)
		s.hmu.Lock()
		s.radiusErr = err
		s.hmu.Unlock()
		return
	}
	s.hmu.Lock()
	s.radiusErr = nil
	s.hmu.Unlock()
}

func itoa(n int) string { return strconv.Itoa(n) }

// AdminPassword is idm_admin's password (the engine's login).
func (s *Server) AdminPassword() (string, error) { return s.adminPassword() }

// ---- are they really up ----

// The ports each service must have open (sockstat's view: the process holds the socket).
func (s *Server) servicePorts(svc string) []sockPort {
	switch svc {
	case "kanidmd":
		return []sockPort{{"tcp", KanidmPort}, {"tcp", s.State().LDAPPort}}
	case "radiusd":
		return []sockPort{{"udp", RadiusPort}}
	}
	return nil
}

type sockPort struct {
	Proto string
	Port  int
}

func (p sockPort) String() string { return fmt.Sprintf("%d/%s", p.Port, p.Proto) }

// CheckService says why a service is not up: its process is not running (rc's onestatus), or
// it holds none of its ports (sockstat). nil: up. Without Real (tests) always nil.
func (s *Server) CheckService(svc string) error {
	if !s.Real {
		return nil
	}
	if !s.running(svc) {
		return errors.New("its process is not running")
	}
	out, err := s.Sys.Run("", "sockstat", "-46")
	if err != nil {
		return fmt.Errorf("sockstat: %v", err)
	}
	var missing []string
	for _, p := range s.servicePorts(svc) {
		if !SockstatHas(out, svc, p.Proto, p.Port) {
			missing = append(missing, p.String())
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("it runs but does not listen on %s", strings.Join(missing, ", "))
	}
	return nil
}

// SockstatHas reads `sockstat -46`: a socket of the command (a prefix of the 10-character
// COMMAND column) with the protocol and local port.
func SockstatHas(out, command, proto string, port int) bool {
	suffix := ":" + strconv.Itoa(port)
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || f[0] == "USER" {
			continue
		}
		if !strings.HasPrefix(command, f[1]) || !strings.HasPrefix(f[4], proto) {
			continue
		}
		if strings.HasSuffix(f[5], suffix) {
			return true
		}
	}
	return false
}

// CheckServices checks both and keeps the result for the status and the alerts.
func (s *Server) CheckServices() map[string]error {
	r := map[string]error{"kanidmd": s.CheckService("kanidmd"), "radiusd": s.CheckService("radiusd")}
	s.hmu.Lock()
	s.svcErr = r
	s.hmu.Unlock()
	return r
}

// waitServices waits up to 20 s for both to be up after a start (ports open a moment after the
// process).
func (s *Server) waitServices() map[string]error {
	var r map[string]error
	for i := 0; i < 10; i++ {
		r = s.CheckServices()
		if r["kanidmd"] == nil && r["radiusd"] == nil {
			break
		}
		s.sleep(2 * time.Second)
	}
	return r
}
