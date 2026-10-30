package auth

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/module/oidc"
	"keelauth/internal/secret"
	"keelauth/internal/sys"
)

// Server is keelauthd.
type Server struct {
	Sys     sys.Sys
	Heads   sys.HeadReader // nil: no seed lookup (tests that do not want one)
	Eng     engine.Engine
	Data    string // DataDir
	Version string
	Log     *log.Logger
	// Real: the system is the VM itself: make certificates, start Kanidm and wait for it.
	// Tests leave it off.
	Real bool
	// Now is the clock (tests set it).
	Now func() time.Time

	// the master key (masterkey.go): box seals with it; nil until it is open
	keyMu      sync.Mutex
	box        *secret.Box
	master     []byte
	mwrap      *Wrapped
	kek        []byte // keel's KEK (from the seed); nil standalone
	unlocked   atomic.Bool
	unlockedCh chan struct{}
	unlockOnce sync.Once
	// LocalKey: a standalone keelAuth's clear copy of the master key ("" = LocalKeyFile)
	LocalKey string
	// keelTZ: keel's time zone (seed, then keel's answer to the registration)
	keelTZ atomic.Value

	mu sync.Mutex // st and its file
	st *State

	radMu sync.Mutex // FreeRADIUS's files

	certMu sync.Mutex // switching certificates (certs.go)

	hmu       sync.Mutex // the rest
	seed      *Seed
	seedDisk  string
	reg       *Registrar
	engineErr error
	radiusErr error
	svcErr    map[string]error // kanidmd, radiusd: why each is not up (process, port); nil = up
	started   time.Time
	// starting: Serve's first bring-up has not finished (Kanidm not prepared yet): the account
	// API answers 503 "starting" meanwhile (keel retries), not answers from a half-made engine
	starting atomic.Bool

	oidcSrv  *oidc.Server // the oidc module's provider (native engine; oidcmod.go)
	sessions *sessions
	backupMu sync.Mutex
	hOnce    sync.Once
	h        http.Handler
}

func osMode(p uint32) os.FileMode { return os.FileMode(p) }

// NewServer loads the state. The master key is opened by OpenMasterKey (Serve does, once it
// knows whether there is a seed); until then keelauthd is locked.
func NewServer(sy sys.Sys, eng engine.Engine, data, version string, lg *log.Logger) (*Server, error) {
	st, created, err := LoadState(sy, data)
	if err != nil {
		return nil, err
	}
	s := &Server{Sys: sy, Eng: eng, Data: data, Version: version, Log: lg, st: st, started: time.Now(),
		sessions: newSessions(), unlockedCh: make(chan struct{})}
	s.sessions.save = s.saveSessions
	if created {
		if err := SaveState(sy, data, st); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// State is the current state (do not change it: use update).
func (s *Server) State() *State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// update changes a copy of the state with f and saves it; bump: an account change (the
// revision the keelNAS sync sees goes up).
func (s *Server) update(f func(st *State) error, bump bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st.Clone()
	if err := f(st); err != nil {
		return err
	}
	if bump {
		st.Revision++
	}
	if err := SaveState(s.Sys, s.Data, st); err != nil {
		return err
	}
	s.st = st
	return nil
}

// bump raises the revision (an account change in the engine only).
func (s *Server) bump() {
	if err := s.update(func(*State) error { return nil }, true); err != nil {
		s.Log.Printf("state: %v", err)
	}
}

// Serve starts everything and serves the API on the Unix socket (root, no key), the internal
// link (HTTP, key) and the LAN (HTTPS). It returns only on an error of the Unix socket.
func (s *Server) Serve(socket string) error {
	if fi, err := os.Stat("/data"); s.Real && (err != nil || !fi.IsDir()) {
		s.Log.Printf("warning: no /data (the data disk): keeping the data in %s on the system disk", s.Data)
	}
	if sd, _ := s.findSeed(); sd != nil {
		s.hmu.Lock()
		s.seed = sd
		s.hmu.Unlock()
		s.ApplyInternal()
	}
	fresh := !s.hasEngineDB()
	sd := s.UseSeed(fresh)
	if err := s.OpenMasterKey(sd); err != nil {
		return fmt.Errorf("master key: %v", err)
	}
	s.dropStoredKey()
	s.bindNative()
	if k := s.State().Engine; k == "" { // fixed at the first start: a later default does not move it
		kind := s.engineKind()
		if err := s.update(func(st *State) error { st.Engine = kind; return nil }, false); err != nil {
			return err
		}
	}
	if sd == nil {
		s.Log.Printf("no seed disk: keelAuth is NOT managed by keel (standalone); manage it on https://<LAN address>/, " +
			"first admin with \"keelauthd admin NAME\" on the console")
	}
	if s.State().Domain == "" {
		if err := s.update(func(st *State) error { st.Domain = DefaultDomain; return nil }, false); err != nil {
			return err
		}
	}
	if s.Real {
		if _, err := s.EnsureTLS(s.State().Domain, s.internalIP()); err != nil {
			s.Log.Printf("tls: %v", err)
		}
	}
	s.starting.Store(true)
	h := s.Handler()
	st := s.State()
	if sd != nil {
		s.StartRegistration(sd)
	}
	if st.Listen != "" && sd != nil { // no seed: no key, nobody to listen for (an old seed's address may be gone)
		go s.serveTCP(st.Listen, s.internalOnly(h), nil)
	}
	if st.HTTPSListen != "" {
		go s.serveTCP(st.HTTPSListen, h, &tls.Config{GetCertificate: s.serverCert, MinVersion: tls.VersionTLS12})
		// http://<address>/ typed into a browser lands on the page too (keel does the same)
		go s.serveKind(DefaultHTTP, redirectHandler(st.HTTPSListen), nil, "HTTP, redirects to HTTPS")
	}
	if s.Real && s.engineKind() == EngineNative {
		if st.LDAPPort > 0 {
			go s.serveLDAP(st.LDAPPort) // the ldap module (ldapmod.go); Kanidm serves LDAP itself otherwise
		}
		go s.serveOIDC(KanidmPort) // the oidc module (oidcmod.go) on the origin's port
	}
	go func() {
		<-s.unlockedCh // a locked master key: nothing works until it is given (POST /unlock)
		s.BringUp()
		s.starting.Store(false)
		s.Schedule()
	}()

	os.Remove(socket)
	ln, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		ln.Close()
		return err
	}
	s.Log.Printf("keelauthd %s: listening on %s", s.Version, socket)
	srv := &http.Server{Handler: s.local(h), ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// dropStoredKey clears the internal link key an older keelauthd kept in state.json: it is on the
// seed, and on the data disk it would open master.wrap.
func (s *Server) dropStoredKey() {
	if s.State().Key == "" {
		return
	}
	if err := s.update(func(st *State) error { st.Key = ""; return nil }, false); err != nil {
		s.Log.Printf("state: %v", err)
		return
	}
	s.Log.Printf("state: the internal link key is no longer kept in state.json (the seed has it)")
}

// linkKey is the internal link key: the seed's; "" without a seed (nobody gets in with a key).
func (s *Server) linkKey() string {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.seed == nil {
		return ""
	}
	return s.seed.Key
}

// hasEngineDB: the engine's data exists (so the domain is fixed): Kanidm's database, or the
// native store's file.
func (s *Server) hasEngineDB() bool {
	p := s.kanidmDir() + "/kanidm.db"
	if n := s.native(); n != nil {
		p = n.Path()
	}
	_, err := os.Stat(p)
	return err == nil
}

// serveTCP keeps trying: at boot the address may come a little later.
func (s *Server) serveTCP(addr string, h http.Handler, tc *tls.Config) {
	kind := "HTTP, key required"
	if tc != nil {
		kind = "HTTPS"
	}
	s.serveKind(addr, h, tc, kind)
}

func (s *Server) serveKind(addr string, h http.Handler, tc *tls.Config, kind string) {
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, TLSConfig: tc,
		ErrorLog: log.New(discard{}, "", 0)} // TLS handshake noise from scanners
	for i := 0; ; i++ {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if i%12 == 0 {
				s.Log.Printf("listen %s: %v (trying again every 5 s)", addr, err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		s.Log.Printf("listening on %s (%s)", addr, kind)
		if tc != nil {
			err = srv.ServeTLS(ln, "", "")
		} else {
			err = srv.Serve(ln)
		}
		s.Log.Printf("listen %s: %v", addr, err)
		time.Sleep(5 * time.Second)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
