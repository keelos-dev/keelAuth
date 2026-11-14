package auth

import (
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Who may use what (docs/02 section 9, 2026-11-14: rights go by group; whoever is put in the
// mail group has a mail address, in the samba group the shares, in the telework group the
// way in from home): **a service belongs to a group, and whoever is in the group has the
// service.** A service (a consumer) is one way out of keelAuth: the shares
// (keelNAS, through keel), LDAP (devices, applications that bind), Wi-Fi (RADIUS), each SSO
// application (oidc:<client>), each sync key (sync:<key id>: a mail server, a gateway). The
// administrator names the group of each (State.ServiceGroups); a member of it, directly or
// through a group in it, may use the service. A service without a group is open to every
// account, as all were before there were groups for them. keelAuth's own page is always open
// (to change the password).
//
// Enforced where each service reads accounts: the LDAP directory, the OIDC provider, the
// RADIUS files, GET /v1/sync/accounts, POST /v1/sync/verify.
//
// Before 2026-11-14 an account had a list of services of its own (ticks in its dialog), a
// group's list added to it, and an account without a list could use everything. Those lists
// are no longer read (state.json may still carry "access"): nobody had more than test
// accounts on them.

const (
	AccessSMB  = "smb"
	AccessLDAP = "ldap"
	AccessWiFi = "wifi"
	accessOIDC = "oidc:"
	accessSync = "sync:"
)

// Consumer is one service accounts can be allowed into.
type Consumer struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // smb, ldap, wifi, oidc, sync
	Name string `json:"name"` // what to show
	// Group: whose members may use it; "" = every account.
	Group string `json:"group"`
	// Missing: the group is named and does not exist (it was deleted): nobody may use the
	// service until it is made again or another is chosen.
	Missing bool `json:"missing,omitempty"`
	// Suggest: the group's usual name, for the page to offer.
	Suggest string `json:"suggest"`
	// Users: how many accounts may use it now.
	Users int `json:"users"`
	// MailDomains: a mail server's (a sync key that offers them, maildomains.go).
	MailDomains []string `json:"mail_domains,omitempty"`
}

// groupWord makes a group name out of what a service is called ("Paperless NGX" →
// paperless-ngx), "" when nothing is left.
func groupWord(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9' && b.Len() > 0:
			b.WriteRune(r)
		case b.Len() > 0 && !strings.HasSuffix(b.String(), "-"):
			b.WriteByte('-')
		}
	}
	word := strings.TrimRight(b.String(), "-")
	if len(word) > 32 {
		word = strings.TrimRight(word[:32], "-")
	}
	if !ValidName(word) {
		return ""
	}
	return word
}

// Consumers lists them: the shares, the two modules', the OIDC clients, the sync keys.
func (s *Server) Consumers() []Consumer {
	st := s.State()
	out := []Consumer{{ID: AccessSMB, Kind: "smb", Name: "keelNAS", Suggest: "samba"}}
	if s.moduleOn("ldap") {
		out = append(out, Consumer{ID: AccessLDAP, Kind: "ldap", Name: "LDAP", Suggest: "ldap"})
	}
	if s.moduleOn("radius") {
		out = append(out, Consumer{ID: AccessWiFi, Kind: "wifi", Name: "Wi-Fi", Suggest: "wifi"})
	}
	if cs, err := s.Eng.OAuth2s(); err == nil && s.moduleOn("oidc") {
		for _, c := range cs {
			name := c.DisplayName
			if name == "" {
				name = c.Name
			}
			// (an application and a group cannot have one name: both are entries of the directory)
			out = append(out, Consumer{ID: accessOIDC + c.Name, Kind: "oidc", Name: name, Suggest: groupWord(c.Name + "-users")})
		}
	}
	for _, k := range st.SyncKeys {
		c := Consumer{ID: accessSync + k.ID, Kind: "sync", Name: k.Name, Suggest: groupWord(k.Name), MailDomains: k.MailDomains}
		if len(k.MailDomains) > 0 {
			c.Suggest = "mail"
		}
		out = append(out, c)
	}
	ac := s.accessChecker()
	names := []string{}
	if us, err := s.Eng.Users(); err == nil {
		for _, u := range us {
			if u.Name != BindAccount {
				names = append(names, u.Name)
			}
		}
	}
	for i := range out {
		c := &out[i]
		c.Group = st.ServiceGroups[c.ID]
		if c.Group != "" {
			_, err := s.Eng.Group(c.Group)
			c.Missing = err != nil
		}
		for _, n := range names {
			if ac.allowed(n, c.ID) {
				c.Users++
			}
		}
	}
	return out
}

func (s *Server) getConsumers(r *http.Request) (any, error) {
	st := s.State()
	return map[string]any{"consumers": s.Consumers(), "mail_domains": s.MailDomains(), "mail_domains_ticked": tickedMailDomains(st)}, nil
}

// putConsumer names the group of a service: {"group": "telework"}, "" = every account. A
// group that does not exist yet is made (empty: nobody has the service until somebody is
// put in).
func (s *Server) putConsumer(r *http.Request) (any, error) {
	id := r.PathValue("id")
	var req struct {
		Group string `json:"group"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	var found *Consumer
	for _, c := range s.Consumers() {
		if c.ID == id {
			found = &c
			break
		}
	}
	if found == nil {
		return nil, notFound("no service %q", id)
	}
	if err := s.setServiceGroup(id, found.Name, strings.ToLower(strings.TrimSpace(req.Group))); err != nil {
		return nil, err
	}
	for _, c := range s.Consumers() {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, notFound("no service %q", id)
}

// setServiceGroup binds the service to the group ("" = unbinds), making the group when it
// is not there. Every reader of accounts must look again: the revision goes up and the
// RADIUS files are written anew.
func (s *Server) setServiceGroup(id, what, group string) error {
	if group != "" {
		if !ValidName(group) {
			return bad("group %q: a lowercase letter, then lowercase letters, digits, - or _ (at most 32)", group)
		}
		if _, err := s.Eng.Group(group); err != nil {
			if _, err := s.Eng.CreateGroup(group, "Members may use "+what); err != nil {
				return err
			}
			s.Log.Printf("access: group %s made for %s", group, id)
		}
	}
	err := s.update(func(st *State) error {
		if group == "" {
			delete(st.ServiceGroups, id)
			return nil
		}
		if st.ServiceGroups == nil {
			st.ServiceGroups = map[string]string{}
		}
		st.ServiceGroups[id] = group
		return nil
	}, true)
	if err != nil {
		return err
	}
	if group == "" {
		s.Log.Printf("access: %s is open to every account", id)
	} else {
		s.Log.Printf("access: %s is for the members of %s", id, group)
	}
	s.accessChanged()
	return nil
}

// servicesOf lists what a group gives its members (the ids of the services bound to it).
func servicesOf(st *State, group string) []string {
	out := []string{}
	for id, g := range st.ServiceGroups {
		if g == group {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// accessChecker answers "may this account use this service" for many accounts at once: the
// memberships are gathered once.
type accessChecker struct {
	st       *State
	memberOf map[string][]string // flattened
}

func (s *Server) accessChecker() accessChecker {
	_, _, memberOf := ldapDir{s}.flat()
	return accessChecker{st: s.State(), memberOf: memberOf}
}

func (a accessChecker) allowed(name, consumer string) bool {
	group := a.st.ServiceGroups[consumer]
	return group == "" || slices.Contains(a.memberOf[name], group)
}

// allowed: one account, one service.
func (s *Server) allowed(name, consumer string) bool {
	return s.accessChecker().allowed(name, consumer)
}

// consumerOfSync is the service a caller of the sync interface reads for: a sync key's own,
// and the shares for keel (which hands the accounts to keelNAS, docs/02 section 3.5) and for
// root on the VM.
func consumerOfSync(c *Caller) string {
	switch {
	case c == nil:
		return ""
	case c.Kind == "sync":
		return accessSync + c.TokenID
	case c.Kind == "keel" || c.Kind == "local":
		return AccessSMB
	}
	return ""
}

// syncKeyOf is the caller's sync key, nil for keel and root.
func (s *Server) syncKeyOf(c *Caller) *Token {
	if c == nil || c.Kind != "sync" {
		return nil
	}
	for _, k := range s.State().SyncKeys {
		if k.ID == c.TokenID {
			k := k
			return &k
		}
	}
	return nil
}

// accessChanged: who may use a service changed: the RADIUS files name the accounts.
func (s *Server) accessChanged() { s.radiusLater() }
