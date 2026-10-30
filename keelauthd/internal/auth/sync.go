package auth

import (
	"net/http"
	"strconv"
)

// The keelNAS sync (docs/02 section 3.5): users with their NT hashes and groups, for a keelNAS
// to make its Samba users from. Only sync keys, keel's key and root may read it.

type SyncUser struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	UID         int      `json:"uid"`
	Enabled     bool     `json:"enabled"`
	NTHash      string   `json:"nt_hash"`
	SetAt       string   `json:"password_set_at"`
	MustChange  bool     `json:"must_change"`
	Groups      []string `json:"groups"`
	Mail        string   `json:"mail"`      // the account's own address
	Addresses   []string `json:"addresses"` // its mailboxes at the offered domains
	// PasswordHash: the password as a PHC string ($pbkdf2-sha256$…), for a mail server's own
	// directory; "" with Kanidm (its hashes stay inside it) or without a password
	PasswordHash string `json:"password_hash,omitempty"`
}

type SyncGroup struct {
	Name    string   `json:"name"`
	GID     int      `json:"gid"`
	Members []string `json:"members"`
}

func (s *Server) getSyncAccounts(r *http.Request) (any, error) {
	st := s.State()
	if q := r.URL.Query().Get("since"); q != "" {
		if n, err := strconv.ParseInt(q, 10, 64); err == nil && n == st.Revision {
			return map[string]any{"revision": st.Revision, "unchanged": true}, nil
		}
	}
	us, err := s.Eng.Users()
	if err != nil {
		return nil, err
	}
	gs, err := s.Eng.Groups()
	if err != nil {
		return nil, err
	}
	users := []SyncUser{}
	ac := s.accessChecker()
	consumer := consumerOfSync(caller(r))
	for _, u := range us {
		if u.Name == BindAccount || (consumer != "" && !ac.allowed(u.Name, consumer)) {
			continue
		}
		su := SyncUser{Name: u.Name, DisplayName: u.DisplayName, UID: u.UID, Enabled: u.Enabled, Groups: u.Groups, Mail: u.Mail, Addresses: addressesOf(st, u.Name)}
		if n := s.native(); n != nil {
			su.PasswordHash = n.PasswordHash(u.Name)
		}
		if su.Groups == nil {
			su.Groups = []string{}
		}
		if d := st.Users[u.Name]; d != nil {
			nt, err := s.box.Open(d.NT)
			if err != nil {
				return nil, err
			}
			su.NTHash, su.SetAt, su.MustChange = nt, d.SetAt, d.MustChange
		}
		users = append(users, su)
	}
	groups := []SyncGroup{}
	for i := range gs {
		g := groupOut(&gs[i])
		groups = append(groups, SyncGroup{Name: g.Name, GID: g.GID, Members: g.Members})
	}
	return map[string]any{"revision": st.Revision, "domain": st.Domain, "users": users, "groups": groups, "mail_domains": mailDomainsOf(st)}, nil
}
