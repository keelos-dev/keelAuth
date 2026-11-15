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
// through a group in it, may use the service. keelAuth's own page is always open (to change
// the password).
//
// **A service nobody chose a group for is closed: nobody may use it** (docs/05 §1.10,
// 2026-11-15: "an account's base is its mailbox; everything else is given"). Forgetting to
// choose must end in "nobody", not in "everybody". "Every account" can be chosen, as a
// choice ("*" in ServiceGroups) the page shows. Before that day a service without a group
// was open to all: closeByDefault writes that down for the services of an older state, once.
//
// The exception is mail (maildomains.go): a mail server without a group serves the accounts
// that have one of its domains ticked.
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

	// everyAccount in ServiceGroups: the service is open to every account, by choice.
	everyAccount = "*"
)

// Scopes: who a service is for (Consumer.Scope).
const (
	scopeNone  = "none"  // nobody: no group chosen yet
	scopeGroup = "group" // the members of Group
	scopeAll   = "all"   // every account
	scopeTicks = "ticks" // a mail server without a group: the accounts with a domain of its ticked
)

// Consumer is one service accounts can be allowed into.
type Consumer struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // smb, ldap, wifi, oidc, sync
	Name string `json:"name"` // what to show
	// Scope: who it is for: "none" (nobody yet), "group" (the members of Group), "all" (every
	// account), "ticks" (a mail server without a group: accounts with a domain ticked).
	Scope string `json:"scope"`
	// Group: whose members may use it, when Scope is "group"; else "".
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
	// Unlimited: it cannot be given a group here: Kanidm, the old engine, serves it itself
	// (LDAP, each SSO application), so every account may use it (docs/02 §9.4).
	Unlimited bool `json:"unlimited,omitempty"`
	// RequireTOTP: a sync key that lets in only accounts with an authenticator app; NoTOTP:
	// those of its accounts without one, who cannot log in through it yet (docs/02 §9.2).
	RequireTOTP bool     `json:"require_totp,omitempty"`
	NoTOTP      []string `json:"no_totp,omitempty"`
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
		c := Consumer{ID: accessSync + k.ID, Kind: "sync", Name: k.Name, Suggest: groupWord(k.Name), MailDomains: k.MailDomains, RequireTOTP: k.RequireTOTP}
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
	kanidm := s.legacyEngine()
	for i := range out {
		c := &out[i]
		if kanidm && (c.Kind == "ldap" || c.Kind == "oidc") {
			c.Unlimited, c.Users, c.Scope = true, len(names), scopeAll
			continue
		}
		switch g := st.ServiceGroups[c.ID]; {
		case g == everyAccount:
			c.Scope = scopeAll
		case g != "":
			c.Scope, c.Group = scopeGroup, g
			_, err := s.Eng.Group(g)
			c.Missing = err != nil
		case len(c.MailDomains) > 0:
			c.Scope = scopeTicks
		default:
			c.Scope = scopeNone
		}
		for _, n := range names {
			if ac.allowed(n, c.ID) {
				c.Users++
				if c.RequireTOTP && !s.totpNeeded(n) {
					c.NoTOTP = append(c.NoTOTP, n)
				}
			}
		}
		sort.Strings(c.NoTOTP)
	}
	return out
}

func (s *Server) getConsumers(r *http.Request) (any, error) {
	st := s.State()
	return map[string]any{"consumers": s.Consumers(), "mail_domains": s.MailDomains(), "mail_domains_ticked": tickedMailDomains(st)}, nil
}

// putConsumer says who a service is for: {"group": "telework"} its members (a group that
// does not exist yet is made, empty: nobody has the service until somebody is put in);
// {"all": true} every account; {"group": ""} nobody (a mail server's: the accounts with a
// domain ticked). Until 2026-11-15 {"group": ""} meant every account: a caller from then
// closes the service, which is the safe way to be wrong.
func (s *Server) putConsumer(r *http.Request) (any, error) {
	id := r.PathValue("id")
	var req struct {
		Group string `json:"group"`
		All   bool   `json:"all"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	group := strings.ToLower(strings.TrimSpace(req.Group))
	if req.All {
		if group != "" {
			return nil, bad("a group or all, not both")
		}
		group = everyAccount
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
	if found.Unlimited && group != "" && group != everyAccount {
		return nil, coded(http.StatusConflict, "engine_kanidm",
			"%s cannot be limited to a group on Kanidm, the old engine (it serves %s itself): deploy a new keelAuth for that", found.Name, found.Name)
	}
	if found.Unlimited {
		group = everyAccount // Kanidm serves it to everybody whatever is written here
	}
	if err := s.setServiceGroup(id, found.Name, group); err != nil {
		return nil, err
	}
	for _, c := range s.Consumers() {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, notFound("no service %q", id)
}

// setServiceGroup binds the service to the group (everyAccount: to all; "": to nobody),
// making the group when it is not there. Every reader of accounts must look again: the revision goes up and the
// RADIUS files are written anew.
func (s *Server) setServiceGroup(id, what, group string) error {
	if group != "" && group != everyAccount {
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
	switch group {
	case "":
		s.Log.Printf("access: %s is closed (no group)", id)
	case everyAccount:
		s.Log.Printf("access: %s is open to every account", id)
	default:
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
	open     bool                // Server.openUnbound
}

func (s *Server) accessChecker() accessChecker {
	_, _, memberOf := ldapDir{s}.flat()
	return accessChecker{st: s.State(), memberOf: memberOf, open: s.openUnbound}
}

func (a accessChecker) allowed(name, consumer string) bool {
	return a.via(name, consumer) != ""
}

// via: how the account has the service: the group's name, everyAccount, viaTick (a mail
// server without a group, a domain of its ticked for the account), "" = it has not.
func (a accessChecker) via(name, consumer string) string {
	switch group := a.st.ServiceGroups[consumer]; {
	case group == everyAccount:
		return everyAccount
	case group != "":
		if slices.Contains(a.memberOf[name], group) {
			return group
		}
	case a.open:
		return everyAccount
	default:
		if id, ok := strings.CutPrefix(consumer, accessSync); ok {
			if d := a.st.Users[name]; d != nil {
				for _, k := range a.st.SyncKeys {
					if k.ID == id && slices.ContainsFunc(k.MailDomains, func(dom string) bool { return slices.Contains(d.MailDomains, dom) }) {
						return viaTick
					}
				}
			}
		}
	}
	return ""
}

const viaTick = "tick"

// closeByDefault: once, on a state from before services were closed by default: every
// service there is now and that has no group is written down as open to every account,
// which is what it was. A mail server's stays as it is (ticks). Modules that are off have
// no service yet: switched on later they start closed, like every new service.
func (s *Server) closeByDefault() error {
	if s.State().ClosedDefault {
		return nil
	}
	ids := []string{AccessSMB}
	if s.moduleOn("ldap") {
		ids = append(ids, AccessLDAP)
	}
	if s.moduleOn("radius") {
		ids = append(ids, AccessWiFi)
	}
	cs, err := s.Eng.OAuth2s()
	if err != nil {
		return err // again at the next start: an application must not be closed by a failed read
	}
	for _, c := range cs {
		ids = append(ids, accessOIDC+c.Name)
	}
	opened := []string{}
	err = s.update(func(st *State) error {
		if st.ClosedDefault {
			return nil
		}
		for _, k := range st.SyncKeys {
			if len(k.MailDomains) == 0 {
				ids = append(ids, accessSync+k.ID)
			}
		}
		if st.ServiceGroups == nil {
			st.ServiceGroups = map[string]string{}
		}
		for _, id := range ids {
			if st.ServiceGroups[id] == "" {
				st.ServiceGroups[id] = everyAccount
				opened = append(opened, id)
			}
		}
		st.ClosedDefault = true
		return nil
	}, false)
	if err == nil && len(opened) > 0 {
		s.Log.Printf("access: services without a group stay open to every account, as before this version: %s", strings.Join(opened, ", "))
	}
	return err
}

// OpenServices: the services open to every account, for the page to remind of (a mail
// server is meant to be: the mailbox is what every account has).
func (s *Server) OpenServices() []Consumer {
	out := []Consumer{}
	for _, c := range s.Consumers() {
		if c.Scope == scopeAll && !c.Unlimited && len(c.MailDomains) == 0 {
			out = append(out, c)
		}
	}
	return out
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
