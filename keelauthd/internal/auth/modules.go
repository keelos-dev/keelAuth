package auth

import (
	"io"
	"net/http"
	"strconv"
)

// modules.go: keelAuth's optional parts (docs/01 "模块化", docs/02 §8.9). The core (accounts,
// groups, access rights, the page, the API, the keel/keelNAS/keelMail interfaces, backups) is
// always there; a module is one way in that the admin switches on or off (Settings → Modules).
// Off = its listener is closed or its service stopped, its consumer is gone from the access
// picks, and its port is not in the status's "ports" (what keel lets in on the LAN NIC). With
// Kanidm as the engine ldap and oidc are Kanidm's own and stay on ("fixed").

type moduleDef struct {
	Name    string
	Default bool // on when the setting says nothing
	Native  bool // keelauthd's own listener (native engine); Kanidm serves it itself otherwise
	Feature bool // a feature module: attributes on an account (features.go), not a way in
}

// (the feature modules are added by features.go's init)
var moduleDefs = []moduleDef{{"ldap", true, true, false}, {"oidc", true, true, false}, {"radius", true, false, false}, {"phone", false, false, false}, {"totp", false, false, false}}

func findModule(name string) (moduleDef, bool) {
	for _, d := range moduleDefs {
		if d.Name == name {
			return d, true
		}
	}
	return moduleDef{}, false
}

// ModuleOut is a module on the API.
type ModuleOut struct {
	Name    string   `json:"name"`
	Kind    string   `json:"kind"` // way (a way in) | feature (attributes on an account)
	Enabled bool     `json:"enabled"`
	Default bool     `json:"default"`
	Fixed   bool     `json:"fixed"` // Kanidm's: cannot be switched
	Ports   []string `json:"ports"` // what it listens on when enabled ("tcp/636")
	Up      *bool    `json:"up,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// moduleFixed: the engine provides it itself (Kanidm's LDAP and OIDC).
func (s *Server) moduleFixed(d moduleDef) bool { return d.Native && s.engineKind() != EngineNative }

// moduleOn: the module is enabled (the setting, else its default; a fixed one is always on).
func (s *Server) moduleOn(name string) bool {
	d, ok := findModule(name)
	if !ok {
		return false
	}
	if s.moduleFixed(d) {
		return true
	}
	if v, ok := s.State().Modules[name]; ok {
		return v
	}
	return d.Default
}

func (s *Server) modulePorts(name string) []string {
	switch name {
	case "ldap":
		if p := s.State().LDAPPort; p > 0 {
			return []string{"tcp/" + strconv.Itoa(p)}
		}
	case "oidc":
		return []string{"tcp/" + strconv.Itoa(KanidmPort)}
	case "radius":
		return []string{"udp/" + strconv.Itoa(RadiusPort)}
	}
	return []string{}
}

// ModulePorts: what the enabled modules listen on, for keel's LAN NIC ACL (besides the page's
// 80 and 443; keelOS docs/80 §44).
func (s *Server) ModulePorts() []string {
	out := []string{}
	for _, d := range moduleDefs {
		if s.moduleOn(d.Name) {
			out = append(out, s.modulePorts(d.Name)...)
		}
	}
	return out
}

// enabledModules: the names of the modules that are on.
func (s *Server) enabledModules() []string {
	out := []string{}
	for _, d := range moduleDefs {
		if s.moduleOn(d.Name) {
			out = append(out, d.Name)
		}
	}
	return out
}

// Modules lists them with their state; svc = CheckServices() (nil: no service check).
func (s *Server) Modules(svc map[string]error) []ModuleOut {
	native := s.engineKind() == EngineNative
	out := []ModuleOut{}
	for _, d := range moduleDefs {
		m := ModuleOut{Name: d.Name, Kind: "way", Enabled: s.moduleOn(d.Name), Default: d.Default, Fixed: s.moduleFixed(d), Ports: s.modulePorts(d.Name)}
		if d.Feature {
			m.Kind = "feature"
		}
		if m.Enabled && !d.Feature {
			var up bool
			var err error
			switch {
			case !s.Real:
				up = true
			case d.Name == "ldap" && native:
				up = ldapListening.Load()
			case d.Name == "oidc" && native:
				up = oidcListening.Load()
			case d.Name == "radius":
				err = svc["radiusd"]
				up = err == nil
			default: // Kanidm's
				err = svc["kanidmd"]
				up = err == nil && s.engineReady()
			}
			m.Up = &up
			if err != nil {
				m.Error = err.Error()
			}
		}
		out = append(out, m)
	}
	return out
}

func (s *Server) getModules(r *http.Request) (any, error) {
	return map[string]any{"modules": s.Modules(s.CheckServices())}, nil
}

// putModule switches a module on or off: PUT /v1/modules/{name} {"enabled": bool}.
func (s *Server) putModule(r *http.Request) (any, error) {
	name := r.PathValue("name")
	d, ok := findModule(name)
	if !ok {
		return nil, notFound("no module %q", name)
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Enabled == nil {
		return nil, bad("enabled: true or false")
	}
	if s.moduleFixed(d) {
		return nil, bad("%s is Kanidm's own here: it cannot be switched off", name)
	}
	if err := s.update(func(st *State) error {
		if st.Modules == nil {
			st.Modules = map[string]bool{}
		}
		st.Modules[name] = *req.Enabled
		return nil
	}, d.Feature); err != nil {
		return nil, err
	}
	state := "off"
	if *req.Enabled {
		state = "on"
	}
	s.Log.Printf("module %s: switched %s", name, state)
	s.applyModule(name, *req.Enabled)
	return map[string]any{"modules": s.Modules(s.CheckServices())}, nil
}

// applyModule makes the switch real: a listener is closed (its serve loop waits until the
// module is on again), radiusd is stopped or brought up.
func (s *Server) applyModule(name string, on bool) {
	if !s.Real {
		return
	}
	switch name {
	case "ldap", "oidc":
		if !on {
			s.closeModule(name)
		}
	case "radius":
		if on {
			go s.radiusLater()
		} else if s.running("radiusd") {
			s.Sys.Run("", "service", "radiusd", "onestop")
		}
	}
}

// setModuleCloser remembers a module's live listener (nil: gone), closeModule closes it.
func (s *Server) setModuleCloser(name string, c io.Closer) {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.modClosers == nil {
		s.modClosers = map[string]io.Closer{}
	}
	if c == nil {
		delete(s.modClosers, name)
		return
	}
	s.modClosers[name] = c
}

func (s *Server) closeModule(name string) {
	s.hmu.Lock()
	c := s.modClosers[name]
	s.hmu.Unlock()
	if c != nil {
		c.Close()
	}
}
