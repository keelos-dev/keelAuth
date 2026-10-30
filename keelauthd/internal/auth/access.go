package auth

import (
	"net/http"
	"slices"
	"sort"
	"strings"
)

// Access rights per service (docs/01 "按服务给用户访问权限"): the administrator ticks what an
// account may use. A consumer is one way out of keelAuth: LDAP (devices, applications that
// bind), Wi-Fi (RADIUS), each SSO application (oidc:<client>), each sync key (sync:<key id>:
// keelNAS, keelMail). keelAuth's own page is always open (to change the password). An account
// without a list (access_set false) may use everything; a group's list adds to its members'.
// Enforced where each consumer reads accounts: the LDAP directory, the OIDC provider, the
// RADIUS files, GET /v1/sync/accounts.

const (
	AccessLDAP = "ldap"
	AccessWiFi = "wifi"
	accessOIDC = "oidc:"
	accessSync = "sync:"
)

// Consumer is one service accounts can be allowed into.
type Consumer struct {
	ID   string `json:"id"`
	Kind string `json:"kind"` // ldap, wifi, oidc, sync
	Name string `json:"name"` // what to show
}

// Consumers lists them: the fixed two, the OIDC clients, the sync keys.
func (s *Server) Consumers() []Consumer {
	out := []Consumer{{AccessLDAP, "ldap", "LDAP"}, {AccessWiFi, "wifi", "Wi-Fi"}}
	if cs, err := s.Eng.OAuth2s(); err == nil {
		for _, c := range cs {
			name := c.DisplayName
			if name == "" {
				name = c.Name
			}
			out = append(out, Consumer{accessOIDC + c.Name, "oidc", name})
		}
	}
	for _, k := range s.State().SyncKeys {
		out = append(out, Consumer{accessSync + k.ID, "sync", k.Name})
	}
	return out
}

func (s *Server) getConsumers(r *http.Request) (any, error) {
	return map[string]any{"consumers": s.Consumers(), "mail_domains": s.MailDomains()}, nil
}

// checkAccess: every id names a consumer.
func (s *Server) checkAccess(ids []string) error {
	known := map[string]bool{}
	for _, c := range s.Consumers() {
		known[c.ID] = true
	}
	for _, id := range ids {
		if !known[id] {
			return bad("access %q: no such service", id)
		}
	}
	return nil
}

func cleanAccess(ids []string) []string {
	out := slices.Clone(ids)
	sort.Strings(out)
	return slices.Compact(out)
}

// accessChecker answers "may this account use this consumer" for many accounts at once:
// the group rights are gathered once.
type accessChecker struct {
	st       *State
	memberOf map[string][]string // flattened
}

func (s *Server) accessChecker() accessChecker {
	_, _, memberOf := ldapDir{s}.flat()
	return accessChecker{st: s.State(), memberOf: memberOf}
}

// list is the account's effective rights (nil, true = everything).
func (a accessChecker) list(name string) ([]string, bool) {
	d := a.st.Users[name]
	if d == nil || !d.AccessSet {
		return nil, true
	}
	out := slices.Clone(d.Access)
	for _, g := range a.memberOf[name] {
		if gd := a.st.Groups[g]; gd != nil {
			out = append(out, gd.Access...)
		}
	}
	return cleanAccess(out), false
}

func (a accessChecker) allowed(name, consumer string) bool {
	l, all := a.list(name)
	return all || slices.Contains(l, consumer)
}

// allowed: one account, one consumer.
func (s *Server) allowed(name, consumer string) bool {
	return s.accessChecker().allowed(name, consumer)
}

// accessOut is what the API shows: the account's own list, null = everything.
func accessOut(d *UserData) []string {
	if d == nil || !d.AccessSet {
		return nil
	}
	if d.Access == nil {
		return []string{}
	}
	return d.Access
}

// consumerOfSync is the consumer id of a sync key's caller.
func consumerOfSync(c *Caller) string {
	if c != nil && c.Kind == "sync" {
		return accessSync + strings.TrimPrefix(c.Name, accessSync)
	}
	return ""
}
