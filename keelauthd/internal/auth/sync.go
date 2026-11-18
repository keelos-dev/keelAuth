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
	// TOTP: the account has an authenticator app set up (and the module is on): what POST
	// /v1/sync/verify will ask a code for.
	TOTP bool `json:"totp"`
	// TOTPSetAt: when that authenticator was set up ("" without one): a gateway that let a
	// computer in on a code drops it when this changes (docs/02 §9.2).
	TOTPSetAt string `json:"totp_set_at"`
	// Features: the feature modules this sync key reads (features.go), when on.
	Features map[string]any `json:"features,omitempty"`
	// Phones: the account's enrolled phones, for a sync key made with phones (docs/04 §8):
	// always a list then ([] = none, or the phone module is off), absent for other keys.
	Phones *[]SyncPhone `json:"phones,omitempty"`
}

// SyncPhone is an enrolled phone as another system needs it to check a signature: the public
// key (base64url of the 65-byte uncompressed P-256 point), never anything secret.
type SyncPhone struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	Created  string `json:"created"`
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
	// a key made without secrets is told who the accounts are, never their hashes
	key := s.syncKeyOf(caller(r))
	secrets := key == nil || !key.NoSecrets
	// a key made with phones is given their public keys (nothing while the module is off)
	phones := key != nil && key.Phones
	byUser := map[string][]SyncPhone{}
	if phones && s.moduleOn("phone") {
		for _, d := range st.Phones {
			byUser[d.User] = append(byUser[d.User], SyncPhone{ID: d.ID, Key: d.Key, Name: d.Name, Platform: d.Platform, Created: d.Created})
		}
	}
	for _, u := range us {
		if u.Name == BindAccount || (consumer != "" && !ac.allowed(u.Name, consumer)) {
			continue
		}
		su := SyncUser{Name: u.Name, DisplayName: u.DisplayName, UID: u.UID, Enabled: u.Enabled, Groups: u.Groups, Mail: u.Mail, Addresses: ac.addresses(u.Name), TOTP: s.totpNeeded(u.Name), TOTPSetAt: s.totpSetAt(u.Name)}
		if n := s.native(); n != nil && secrets {
			su.PasswordHash = n.PasswordHash(u.Name)
		}
		if key != nil && len(key.Features) > 0 {
			su.Features = s.featureValues(u.Name, key.Features)
		}
		if su.Groups == nil {
			su.Groups = []string{}
		}
		if phones {
			l := byUser[u.Name]
			if l == nil {
				l = []SyncPhone{}
			}
			su.Phones = &l
		}
		if d := st.Users[u.Name]; d != nil {
			nt, err := s.box.Open(d.NT)
			if err != nil {
				return nil, err
			}
			su.NTHash, su.SetAt, su.MustChange = nt, d.SetAt, d.MustChange
			if !secrets {
				su.NTHash = ""
			}
		}
		users = append(users, su)
	}
	groups := []SyncGroup{}
	for i := range gs {
		g := groupOut(&gs[i])
		groups = append(groups, SyncGroup{Name: g.Name, GID: g.GID, Members: g.Members})
	}
	out := map[string]any{"revision": st.Revision, "domain": st.Domain, "users": users, "groups": groups, "mail_domains": mailDomainsOf(st), "secrets": secrets}
	if phones {
		// phone_origin: the first line after the prefix of what the phones sign (phone.RPMessage)
		out["phones"], out["phone_origin"] = true, s.Origin()
	}
	return out, nil
}
