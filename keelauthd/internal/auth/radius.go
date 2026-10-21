package auth

import (
	"net"
	"net/http"
	"regexp"
	"strings"

	"keelauth/internal/secret"
)

// RADIUS (FreeRADIUS, MSCHAPv2 against the NT hash): the clients (APs, VPN gateways) and who
// may use it. FreeRADIUS's files are generated (services.go).

// RadiusClientOut is a client in the API (with its secret: it is needed on the AP).
type RadiusClientOut struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	Secret  string `json:"secret"`
}

// secretRE: what FreeRADIUS takes inside quotes in clients.conf without escaping.
var secretRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'()*+,./:;<=>?@\[\]^_{|}~-]{8,64}$`)

func validAddress(a string) bool {
	if ip := net.ParseIP(a); ip != nil {
		return true
	}
	_, _, err := net.ParseCIDR(a)
	return err == nil
}

func (s *Server) radiusOut() (map[string]any, error) {
	st := s.State()
	cs := []RadiusClientOut{}
	for _, c := range st.Radius.Clients {
		sec, err := s.box.Open(c.Secret)
		if err != nil {
			return nil, err
		}
		cs = append(cs, RadiusClientOut{c.Name, c.Address, sec})
	}
	users, missing := 0, []string{}
	if us, err := s.Eng.Users(); err == nil {
		for _, u := range us {
			if !u.Enabled || u.Name == BindAccount || (st.Radius.Group != "" && !contains(u.Groups, st.Radius.Group)) {
				continue
			}
			if d := st.Users[u.Name]; d != nil && d.NT != "" {
				users++
			} else {
				missing = append(missing, u.Name)
			}
		}
	}
	out := map[string]any{"port": RadiusPort, "group": st.Radius.Group, "clients": cs, "users": users, "missing_nt": missing,
		"addresses": s.addresses(),
		// what phones and laptops check (WPA2/3-Enterprise): the server certificate's name and the CA
		"server_name": st.Domain, "eap": "PEAP", "inner": "MSCHAPv2", "office_cert": s.officeActive()}
	if b, err := s.anchorPEM(); err == nil {
		if c, err := pemCerts(b); err == nil && len(c) > 0 {
			out["ca"] = s.certInfo(c[0])
		}
	}
	return out, nil
}

func (s *Server) getRadius(r *http.Request) (any, error) { return s.radiusOut() }

func (s *Server) putRadius(r *http.Request) (any, error) {
	var req struct {
		Group string `json:"group"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Group != "" {
		if _, err := s.lookupGroup(req.Group); err != nil {
			return nil, bad("no group %q", req.Group)
		}
	}
	if err := s.update(func(st *State) error { st.Radius.Group = req.Group; return nil }, false); err != nil {
		return nil, err
	}
	if err := s.ApplyRadius(); err != nil {
		return nil, err
	}
	return s.radiusOut()
}

func (s *Server) postRadiusClient(r *http.Request) (any, error) {
	var req struct {
		Name    string `json:"name"`
		Address string `json:"address"`
		Secret  string `json:"secret"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Address = strings.TrimSpace(req.Address)
	switch {
	case !ValidName(req.Name) || req.Name == "localhost":
		return nil, bad("client name %q: lower-case letters, digits, - and _, a letter first, at most 32", req.Name)
	case !validAddress(req.Address):
		return nil, bad("address %q: an IP address or a network (192.168.1.0/24)", req.Address)
	case req.Secret != "" && !secretRE.MatchString(req.Secret):
		return nil, bad("the shared secret: 8 to 64 letters, digits and punctuation, no spaces or quotes")
	}
	if req.Secret == "" {
		req.Secret = secret.Random(12)
	}
	err := s.update(func(st *State) error {
		if st.radiusClient(req.Name) != nil {
			return conflict("there is a RADIUS client %q already", req.Name)
		}
		st.Radius.Clients = append(st.Radius.Clients, RadiusClient{Name: req.Name, Address: req.Address, Secret: s.box.Seal(req.Secret)})
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	if err := s.ApplyRadius(); err != nil {
		return nil, err
	}
	return RadiusClientOut{req.Name, req.Address, req.Secret}, nil
}

func (s *Server) patchRadiusClient(r *http.Request) (any, error) {
	name := r.PathValue("name")
	var req struct {
		Address *string `json:"address"`
		Secret  *string `json:"secret"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Address != nil && !validAddress(strings.TrimSpace(*req.Address)) {
		return nil, bad("address %q: an IP address or a network (192.168.1.0/24)", *req.Address)
	}
	if req.Secret != nil && *req.Secret != "" && !secretRE.MatchString(*req.Secret) {
		return nil, bad("the shared secret: 8 to 64 letters, digits and punctuation, no spaces or quotes")
	}
	var out RadiusClientOut
	err := s.update(func(st *State) error {
		c := st.radiusClient(name)
		if c == nil {
			return notFound("no RADIUS client %q", name)
		}
		if req.Address != nil {
			c.Address = strings.TrimSpace(*req.Address)
		}
		if req.Secret != nil {
			sec := *req.Secret
			if sec == "" {
				sec = secret.Random(12)
			}
			c.Secret = s.box.Seal(sec)
		}
		sec, _ := s.box.Open(c.Secret)
		out = RadiusClientOut{c.Name, c.Address, sec}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	if err := s.ApplyRadius(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Server) deleteRadiusClient(r *http.Request) (any, error) {
	name := r.PathValue("name")
	err := s.update(func(st *State) error {
		for i, c := range st.Radius.Clients {
			if c.Name == name {
				st.Radius.Clients = append(st.Radius.Clients[:i], st.Radius.Clients[i+1:]...)
				return nil
			}
		}
		return notFound("no RADIUS client %q", name)
	}, false)
	if err != nil {
		return nil, err
	}
	if err := s.ApplyRadius(); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}
