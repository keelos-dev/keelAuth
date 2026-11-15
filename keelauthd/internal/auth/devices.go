package auth

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"keelauth/internal/engine"
)

// LDAP device accounts (keelOS docs/54 D4, docs/02 section 7.10): one per printer, Linux machine
// or application, made and revoked on its own. Each is a Kanidm service account in the groups
// that read mail and the POSIX attributes, and binds with a read-only API token (bind DN
// "dn=token", the token as the password). A password bind (a person, keelAuth's shared
// keelauth-ldap) is bounded by the anonymous account's rights in Kanidm and gets no mail: a
// printer's address book or GitLab need the token.

// DeviceBindDN is what a device account enters as its bind DN.
const DeviceBindDN = "dn=token"

// deviceGroups are the engine groups a device account is put in.
var deviceGroups = []string{engine.MailRead, engine.UnixRead}

// DeviceOut is a device account in the API; Password only right after it was made.
type DeviceOut struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created"`
	PasswordAt  string `json:"password_set_at"`
	BindDN      string `json:"bind_dn"`
	Password    string `json:"password,omitempty"`
	// Features: the feature modules whose LDAP attributes it reads (docs/02 §10.4).
	Features []string `json:"features"`
	// Service: the service whose people it finds ("" = LDAP's; "sync:<id>" = a mail
	// server's, docs/02 §9.6).
	Service string `json:"service"`
	// Missing: keelAuth has it, the engine not (a restored older backup): make a new password
	// or delete it
	Missing bool `json:"missing,omitempty"`
}

func (d *Device) out() DeviceOut {
	return DeviceOut{Name: d.Name, Description: d.Description, Created: d.Created, PasswordAt: d.PasswordAt, BindDN: DeviceBindDN,
		Features: append([]string{}, d.Features...), Service: d.Service}
}

func (s *Server) devicesOut() []DeviceOut {
	st := s.State()
	have := map[string]bool{}
	if sas, err := s.Eng.ServiceAccounts(); err == nil {
		for _, sa := range sas {
			have[sa.Name] = true
		}
	} else {
		have = nil
	}
	out := []DeviceOut{}
	for _, d := range st.Devices {
		o := d.out()
		o.Missing = have != nil && !have[d.Name]
		out = append(out, o)
	}
	return out
}

// deviceService checks the service a device account is to stand for: "" or "ldap" = LDAP
// itself (""), else a service there is. Only keelAuth's own LDAP server can do it.
func (s *Server) deviceService(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || id == AccessLDAP {
		return "", nil
	}
	if s.legacyEngine() {
		return "", coded(http.StatusConflict, "engine_kanidm", "a device account cannot stand for another service on Kanidm, the old engine (it serves LDAP itself)")
	}
	for _, c := range s.Consumers() {
		if c.ID == id {
			return id, nil
		}
	}
	return "", bad("no service %q (GET /v1/consumers lists them)", id)
}

func (st *State) device(name string) *Device {
	for i := range st.Devices {
		if st.Devices[i].Name == name {
			return &st.Devices[i]
		}
	}
	return nil
}

func (s *Server) getDevices(r *http.Request) (any, error) {
	return map[string]any{"devices": s.devicesOut(), "bind_dn": DeviceBindDN}, nil
}

func (s *Server) postDevice(r *http.Request) (any, error) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Features    []string `json:"features"`
		Service     string   `json:"service"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Name, req.Description = strings.TrimSpace(req.Name), strings.TrimSpace(req.Description)
	feats, err := checkKeyFeatures(req.Features)
	if err != nil {
		return nil, err
	}
	service, err := s.deviceService(req.Service)
	if err != nil {
		return nil, err
	}
	switch {
	case !ValidName(req.Name) || reserved(req.Name):
		return nil, bad("device name %q: lower-case letters, digits, - and _, a letter first, at most 32 (not a name keelAuth or Kanidm uses)", req.Name)
	case len(req.Description) > 200:
		return nil, bad("the description: at most 200 characters")
	case s.State().device(req.Name) != nil:
		return nil, conflict("there is a device account %q already", req.Name)
	}
	disp := "Device " + req.Name
	if req.Description != "" {
		disp = req.Description
	}
	if err := s.Eng.CreateServiceAccount(req.Name, disp, deviceGroups); err != nil {
		if errors.Is(err, engine.ErrExists) {
			return nil, conflict("the name %q is taken (a user, group or another account has it)", req.Name)
		}
		return nil, err
	}
	tok, err := s.Eng.NewAPIToken(req.Name, "keelauth device "+req.Name)
	if err != nil {
		s.Eng.DeleteServiceAccount(req.Name)
		return nil, err
	}
	now := s.now().Format(time.RFC3339)
	d := Device{Name: req.Name, Description: req.Description, Created: now, PasswordAt: now, Features: feats, Service: service}
	if err := s.update(func(st *State) error { st.Devices = append(st.Devices, d); return nil }, false); err != nil {
		s.Eng.DeleteServiceAccount(req.Name)
		return nil, err
	}
	s.Log.Printf("ldap: device account %s made", req.Name)
	out := d.out()
	out.Password = tok
	return out, nil
}

// patchDevice: PATCH /v1/ldap/devices/{name} {"description", "features", "service"}: what is given changes.
func (s *Server) patchDevice(r *http.Request) (any, error) {
	name := r.PathValue("name")
	var req struct {
		Description *string   `json:"description"`
		Features    *[]string `json:"features"`
		Service     *string   `json:"service"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	service := ""
	if req.Service != nil {
		var err error
		if service, err = s.deviceService(*req.Service); err != nil {
			return nil, err
		}
	}
	var feats []string
	if req.Features != nil {
		var err error
		if feats, err = checkKeyFeatures(*req.Features); err != nil {
			return nil, err
		}
	}
	if req.Description != nil {
		*req.Description = strings.TrimSpace(*req.Description)
		if len(*req.Description) > 200 {
			return nil, bad("the description: at most 200 characters")
		}
	}
	var out DeviceOut
	err := s.update(func(st *State) error {
		x := st.device(name)
		if x == nil {
			return notFound("no device account %q", name)
		}
		if req.Description != nil {
			x.Description = *req.Description
		}
		if req.Features != nil {
			x.Features = feats
		}
		if req.Service != nil {
			x.Service = service
		}
		out = x.out()
		return nil
	}, false)
	return out, err
}

// postDevicePassword gives a device account a new token (the old one stops working at once).
// An account keelAuth knows but the engine lost (a restored older backup) is made again.
func (s *Server) postDevicePassword(r *http.Request) (any, error) {
	name := r.PathValue("name")
	d := s.State().device(name)
	if d == nil {
		return nil, notFound("no device account %q", name)
	}
	tok, err := s.Eng.NewAPIToken(name, "keelauth device "+name)
	if errors.Is(err, engine.ErrNotFound) {
		disp := "Device " + name
		if d.Description != "" {
			disp = d.Description
		}
		if err = s.Eng.CreateServiceAccount(name, disp, deviceGroups); err == nil {
			tok, err = s.Eng.NewAPIToken(name, "keelauth device "+name)
		}
	}
	if err != nil {
		return nil, err
	}
	var out DeviceOut
	err = s.update(func(st *State) error {
		x := st.device(name)
		if x == nil {
			return notFound("no device account %q", name)
		}
		x.PasswordAt = s.now().Format(time.RFC3339)
		out = x.out()
		out.Password = tok
		return nil
	}, false)
	return out, err
}

func (s *Server) deleteDevice(r *http.Request) (any, error) {
	name := r.PathValue("name")
	if s.State().device(name) == nil {
		return nil, notFound("no device account %q", name)
	}
	if err := s.Eng.DeleteServiceAccount(name); err != nil && !errors.Is(err, engine.ErrNotFound) {
		return nil, err
	}
	err := s.update(func(st *State) error {
		for i := range st.Devices {
			if st.Devices[i].Name == name {
				st.Devices = append(st.Devices[:i], st.Devices[i+1:]...)
				break
			}
		}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	s.Log.Printf("ldap: device account %s deleted", name)
	return map[string]any{}, nil
}
