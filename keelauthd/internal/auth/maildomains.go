package auth

import (
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Mail domains follow keelMail (docs/01 "邮件" and "域名跟着 keelMail 走"): a mail server
// registers the domains it serves through its sync key (PUT /v1/sync/offers); the user
// dialog then offers them as boxes to tick, and a ticked domain gives the account the
// mailbox <name>@<domain>. A domain the mail server drops disappears from every account.
// The account's own "mail" field (an address anywhere) stays what it was.

var mailDomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// MailDomains is every domain a sync key offers (sorted, unique).
func (s *Server) MailDomains() []string {
	return mailDomainsOf(s.State())
}

func mailDomainsOf(st *State) []string {
	out := []string{}
	for _, k := range st.SyncKeys {
		out = append(out, k.MailDomains...)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// tickedMailDomains: the domains of the mail servers that have no group (access.go): a
// mailbox there is a tick in the account's dialog, as before services had groups.
func tickedMailDomains(st *State) []string {
	out := []string{}
	for _, k := range st.SyncKeys {
		if st.ServiceGroups[accessSync+k.ID] == "" {
			out = append(out, k.MailDomains...)
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// addresses is the account's mailboxes. A mail server with a group: its members have
// <name>@<domain> at every domain it offers ("whoever is in the mail group has a mail
// address"). One open to every account: everybody has (docs/05 §1.10: "an account is a
// mailbox"; a new account has its addresses at once). A mail server without either: at each
// domain ticked for the account.
func (a accessChecker) addresses(name string) []string {
	out := []string{}
	var ticked []string
	if d := a.st.Users[name]; d != nil {
		ticked = d.MailDomains
	}
	for _, k := range a.st.SyncKeys {
		group := a.st.ServiceGroups[accessSync+k.ID]
		for _, dom := range k.MailDomains {
			if group == everyAccount || (group != "" && slices.Contains(a.memberOf[name], group)) || (group == "" && slices.Contains(ticked, dom)) {
				out = append(out, name+"@"+dom)
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// cleanList: sorted, each once.
func cleanList(l []string) []string {
	out := slices.Clone(l)
	sort.Strings(out)
	return slices.Compact(out)
}

// checkMailDomains: every domain is one keelMail offers.
func (s *Server) checkMailDomains(doms []string) error {
	offered := s.MailDomains()
	for _, d := range doms {
		if !slices.Contains(offered, d) {
			return bad("mail domain %q: no mail server offers it", d)
		}
	}
	return nil
}

// putSyncOffers: a sync key says what it offers: {"mail_domains": [...]}. A domain no key
// offers any more is taken off every account.
func (s *Server) putSyncOffers(r *http.Request) (any, error) {
	c := caller(r)
	if c == nil || c.Kind != "sync" {
		return nil, coded(http.StatusForbidden, "scope", "only a sync key registers what it offers")
	}
	var req struct {
		MailDomains []string `json:"mail_domains"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	doms := []string{}
	for _, d := range req.MailDomains {
		d = strings.ToLower(strings.TrimSpace(d))
		if !mailDomainRE.MatchString(d) {
			return nil, bad("mail domain %q: not a domain name", d)
		}
		doms = append(doms, d)
	}
	sort.Strings(doms)
	doms = slices.Compact(doms)
	var gone []string
	cleared := 0
	err := s.update(func(st *State) error {
		for i := range st.SyncKeys {
			if st.SyncKeys[i].ID == c.TokenID {
				st.SyncKeys[i].MailDomains = doms
			}
		}
		offered := mailDomainsOf(st)
		for name, d := range st.Users {
			kept := slices.DeleteFunc(slices.Clone(d.MailDomains), func(x string) bool { return !slices.Contains(offered, x) })
			if len(kept) != len(d.MailDomains) {
				for _, x := range d.MailDomains {
					if !slices.Contains(kept, x) && !slices.Contains(gone, x) {
						gone = append(gone, x)
					}
				}
				cleared++
				st.Users[name].MailDomains = kept
			}
		}
		return nil
	}, true)
	if err != nil {
		return nil, err
	}
	if cleared > 0 {
		s.Log.Printf("mail: domains %s no longer offered: taken off %d accounts", strings.Join(gone, ", "), cleared)
	}
	return map[string]any{"mail_domains": s.MailDomains()}, nil
}
