package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Alert is something wrong now (GET /v1/alerts).
type Alert struct {
	Code   string `json:"code"`
	Level  string `json:"level"` // error | warning
	Object string `json:"object"`
	Text   string `json:"text"`
}

// Alerts are computed when asked, from what keelauthd sees now.
func (s *Server) Alerts() []Alert {
	out := []Alert{}
	mk := s.masterKeyInfo()
	if mk.Locked {
		return append(out, Alert{"locked", "error", "master_key",
			"keelAuth is locked: its master key needs the recovery key (keelOS: Accounts → Recovery key) or its recovery passphrase"})
	}
	if mk.Unprotected {
		out = append(out, Alert{"master_key_unprotected", "warning", "master_key",
			"set a recovery passphrase (Settings → Recovery): until then the key that protects the NT hashes is in clear on the data disk and in every backup"})
	}
	s.hmu.Lock()
	eerr, rerr := s.engineErr, s.radiusErr
	s.hmu.Unlock()
	if eerr != nil {
		out = append(out, Alert{"engine", "error", "kanidmd", "Kanidm is not ready: " + eerr.Error()})
	}
	if _, _, _, fb := s.OriginInfo(); fb != "" {
		out = append(out, Alert{"origin_ip_fallback", "warning", "origin", fb})
	}
	svc := s.CheckServices()
	for _, n := range s.serviceNames() {
		if svc[n] != nil {
			out = append(out, Alert{"service_down", "error", n, n + " is not up: " + svc[n].Error()})
		}
	}
	if rerr != nil {
		out = append(out, Alert{"radius_behind", "warning", "radiusd", "FreeRADIUS's users are not up to date: " + rerr.Error()})
	}
	if eerr == nil {
		st := s.State()
		if us, err := s.Eng.Users(); err == nil {
			var miss []string
			for _, u := range us {
				if u.Enabled && u.Name != BindAccount && (st.Users[u.Name] == nil || st.Users[u.Name].NT == "") {
					miss = append(miss, u.Name)
				}
			}
			if len(miss) > 0 {
				out = append(out, Alert{"missing_nt", "warning", strings.Join(miss, ","),
					"no NT hash (Wi-Fi and shares will not work) until the password is set again in keelAuth: " + strings.Join(miss, ", ")})
			}
		}
		if g, err := s.Eng.Group(AdminGroup); err == nil && len(g.Members) == 0 {
			out = append(out, Alert{"no_admin", "warning", AdminGroup, "nobody is in " + AdminGroup + ": only keel (and the console) can manage keelAuth"})
		}
	}
	out = append(out, s.certAlerts()...)
	st := s.State()
	if last, err := time.Parse(time.RFC3339, st.LastBackup); err != nil {
		if time.Since(s.started) > time.Hour {
			out = append(out, Alert{"no_backup", "warning", "", "no backup yet"})
		}
	} else if s.now().Sub(last) > 48*time.Hour {
		out = append(out, Alert{"old_backup", "warning", "", "the last backup is from " + st.LastBackup})
	}
	return out
}

func (s *Server) getAlerts(r *http.Request) (any, error) {
	return map[string]any{"alerts": s.Alerts()}, nil
}

func (s *Server) getStatus(r *http.Request) (any, error) {
	st := s.State()
	counts := map[string]int{"users": 0, "groups": 0, "oidc": 0, "radius_clients": len(st.Radius.Clients)}
	if us, err := s.Eng.Users(); err == nil {
		counts["users"] = len(us)
		for _, u := range us {
			if u.Name == BindAccount {
				counts["users"]--
			}
		}
	}
	if gs, err := s.Eng.Groups(); err == nil {
		counts["groups"] = len(gs)
	}
	if cs, err := s.Eng.OAuth2s(); err == nil {
		counts["oidc"] = len(cs)
	}
	// each service on its own: up = process running and its ports open (and for Kanidm its
	// REST answering keelauthd); service_errors says why one is not
	svc := s.CheckServices()
	kind := s.engineKind()
	services := map[string]bool{"radiusd": svc["radiusd"] == nil}
	engineName := "store" // the native store: up = keelauthd's bring-up went through
	if kind != EngineNative {
		engineName = "kanidmd"
	}
	services[engineName] = svc[engineName] == nil && s.engineReady()
	if kind == EngineNative { // the modules' listeners
		services["ldap"] = ldapListening.Load() || !s.Real
		services["oidc"] = oidcListening.Load() || !s.Real
	}
	serrs := map[string]string{}
	for n, e := range svc {
		if e != nil {
			serrs[n] = e.Error()
		}
	}
	s.hmu.Lock()
	if eerr := s.engineErr; eerr != nil && serrs[engineName] == "" {
		serrs[engineName] = "keelauthd cannot use it: " + eerr.Error()
	}
	s.hmu.Unlock()
	mode, _, _, _ := s.OriginInfo()
	out := map[string]any{
		"version": s.versionString(), "hostname": s.hostname(), "domain": st.Domain, "origin": s.Origin(), "origin_mode": mode, "engine": kind,
		"addresses": s.addresses(), "uptime_s": int64(time.Since(s.started).Seconds()), "services": services,
		"service_errors": serrs,
		"counts":         counts, "last_backup": st.LastBackup, "alerts": len(s.Alerts()), "fingerprint": s.Fingerprint(),
		"ldap_port": st.LDAPPort, "radius_port": RadiusPort, "kanidm_port": KanidmPort,
	}
	minLen, strength := st.PasswordPolicy()
	out["password_policy"] = map[string]any{"min_length": minLen, "strength": strength}
	if k := s.keelStatus(); k != nil {
		out["keel"] = k
	}
	s.hmu.Lock()
	out["managed_by_keel"] = s.seed != nil // false: no seed disk, a standalone keelAuth
	s.hmu.Unlock()
	out["master_key"] = s.masterKeyInfo()
	out["timezone"] = s.zoneFor(r)
	return out, nil
}

func (s *Server) settingsOut(r *http.Request) map[string]any {
	st := s.State()
	tz := st.Timezone
	if tz == "" {
		tz = "UTC"
	}
	mode, _, _, _ := s.OriginInfo()
	minLen, strength := st.PasswordPolicy()
	return map[string]any{"domain": st.Domain, "origin": s.Origin(), "origin_mode": mode, "https_listen": st.HTTPSListen,
		"backup_keep": st.BackupKeep, "ldap_port": st.LDAPPort, "fingerprint": s.Fingerprint(),
		"password_min_length": minLen, "password_strength": strength,
		// timezone: keelAuth's own (standalone); managed by keel the page uses keel's (timezone_in_use)
		"timezone": tz, "timezone_in_use": s.zoneFor(r), "timezone_from_keel": s.managed(),
		"master_key": s.masterKeyInfo(), "brand": st.Brand.out()}
}

func (s *Server) getSettings(r *http.Request) (any, error) { return s.settingsOut(r), nil }

func (s *Server) putSettings(r *http.Request) (any, error) {
	var req struct {
		BackupKeep        *int    `json:"backup_keep"`
		Timezone          *string `json:"timezone"`
		PasswordMinLength *int    `json:"password_min_length"`
		PasswordStrength  *string `json:"password_strength"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	// the password rules go to Kanidm's config.toml; a change restarts kanidmd (a few seconds)
	if req.PasswordMinLength != nil || req.PasswordStrength != nil {
		if req.PasswordMinLength != nil && (*req.PasswordMinLength < 8 || *req.PasswordMinLength > 64) {
			return nil, bad("password_min_length: 8 to 64")
		}
		if req.PasswordStrength != nil {
			if _, ok := passwordScores[*req.PasswordStrength]; !ok {
				return nil, bad("password_strength: strict, normal or length")
			}
		}
		if err := s.update(func(st *State) error {
			if req.PasswordMinLength != nil {
				st.PasswordMinLength = *req.PasswordMinLength
			}
			if req.PasswordStrength != nil {
				st.PasswordStrength = *req.PasswordStrength
			}
			return nil
		}, false); err != nil {
			return nil, err
		}
		s.applyPolicy()
		if s.Real && s.engineKind() != EngineNative {
			if err := s.StartKanidm(false); err != nil {
				return nil, fmt.Errorf("kanidmd: %v", err)
			}
		}
	}
	if req.Timezone != nil {
		z := *req.Timezone
		if z == "" {
			z = "UTC"
		}
		if !validZone(z) {
			return nil, bad("timezone %q: not a zone name like Asia/Tokyo", *req.Timezone)
		}
		if z == "UTC" {
			z = ""
		}
		if err := s.update(func(st *State) error { st.Timezone = z; return nil }, false); err != nil {
			return nil, err
		}
	}
	if req.BackupKeep != nil {
		if *req.BackupKeep < 1 || *req.BackupKeep > 365 {
			return nil, bad("backup_keep: 1 to 365")
		}
		if err := s.update(func(st *State) error { st.BackupKeep = *req.BackupKeep; return nil }, false); err != nil {
			return nil, err
		}
		s.prune()
	}
	return s.settingsOut(r), nil
}
