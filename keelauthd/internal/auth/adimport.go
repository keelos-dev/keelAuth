package auth

// Importing the accounts of a Windows AD (docs/07). The directory is read once into memory
// (adimport.Read), the administrator's choices are applied to it (adimport.Map) with
// keelAuth's own rules for names, and the sound ticked rows become accounts the way
// POST /v1/users makes them. Rows with a problem stay behind, to be corrected and imported
// with the next run.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"keelauth/internal/adimport"
	"keelauth/internal/module/ldap"
)

const adReadKept = 15 * time.Minute

// adRead is one directory read, kept in memory only.
type adRead struct {
	at   time.Time
	dir  *adimport.Directory
	made []adMade // every account made from it, with its initial password
}

// adMade is one imported account, for the answer and the password table.
type adMade struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"display_name"`
	Mail        string   `json:"mail"`
	Addresses   []string `json:"addresses"`
	Password    string   `json:"password"`
}

func realADRead(ctx context.Context, address, user, password, pin string) (*adimport.Directory, string, error) {
	u, err := ldap.DialUpstream(ctx, address, pin)
	if err != nil {
		return nil, "", err
	}
	defer u.Close()
	if err := u.Bind(user, password); err != nil {
		return nil, u.Fingerprint, err
	}
	d, err := adimport.Read(u)
	return d, u.Fingerprint, err
}

// adGet finds a read by id and forgets the old ones.
func (s *Server) adGet(id string) (*adRead, error) {
	s.adMu.Lock()
	defer s.adMu.Unlock()
	for k, r := range s.adReads {
		if s.now().Sub(r.at) > adReadKept {
			delete(s.adReads, k)
		}
	}
	if r := s.adReads[id]; r != nil {
		r.at = s.now() // kept for 15 minutes after its last use: a long import does not lose it half-way
		return r, nil
	}
	return nil, coded(http.StatusNotFound, "ad_read_gone", "what was read from the AD is no longer kept (15 minutes unused): read it again")
}

func (s *Server) adEnv() adimport.Env {
	return adimport.Env{
		HaveUser: func(n string) bool {
			if reserved(n) {
				return true
			}
			u, err := s.Eng.User(n)
			return err == nil && u != nil
		},
		HaveGroup: func(n string) bool {
			g, err := s.Eng.Group(n)
			return err == nil && g != nil
		},
		ValidUser:   ValidUserName,
		ValidGroup:  func(n string) bool { return ValidName(n) && !reserved(n) },
		MailDomains: s.MailDomains(),
	}
}

// adPlan is Map with keelAuth's own checks on top: a group and an account cannot share a name.
func (s *Server) adPlan(rd *adRead, m adimport.Mapping) *adimport.Plan {
	p := adimport.Map(rd.dir, m, s.adEnv())
	names := map[string]bool{}
	for _, r := range p.Rows {
		if r.Ticked || r.Exists {
			names[r.Name] = true
		}
	}
	for i := range p.Groups {
		g := &p.Groups[i]
		if g.Problem != "" || g.Exists {
			continue
		}
		u, _ := s.Eng.User(g.Name)
		if names[g.Name] || u != nil {
			g.SetProblem("group_is_account", "an account has this name: a group needs another")
			if g.Ticked {
				p.Problems++
			}
		}
	}
	return p
}

func (s *Server) postADRead(r *http.Request) (any, error) {
	var req struct {
		Address     string `json:"address"`
		User        string `json:"user"`
		Password    string `json:"password"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Address = strings.TrimSpace(req.Address)
	if req.Address == "" || req.User == "" || req.Password == "" {
		return nil, bad("address, user and password of the AD are all needed")
	}
	read := s.ADRead
	if read == nil {
		read = realADRead
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	dir, fp, err := read(ctx, req.Address, req.User, req.Password, req.Fingerprint)
	var pin *ldap.PinError
	switch {
	case errors.As(err, &pin):
		// not an error: the administrator looks at the fingerprint and sends it back
		return map[string]any{"confirm_certificate": pin.Got}, nil
	case errors.Is(err, ldap.ErrUpstreamLogin):
		return nil, coded(http.StatusBadRequest, "ad_login", "the AD refused this account and password")
	case err != nil:
		return nil, coded(http.StatusBadGateway, "ad_unreachable", "reading the AD at %s: %v", req.Address, err)
	}
	var b [16]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	rd := &adRead{at: s.now(), dir: dir}
	s.adMu.Lock()
	if s.adReads == nil {
		s.adReads = map[string]*adRead{}
	}
	s.adReads[id] = rd
	s.adMu.Unlock()
	s.Log.Printf("AD import: read %d accounts and %d groups of %s (%s)", len(dir.People), len(dir.Groups), dir.Domain, req.Address)
	return map[string]any{"id": id, "fingerprint": fp, "domain": dir.Domain, "mail_domains": dir.MailDomains(),
		"our_mail_domains": s.MailDomains(), "kept_minutes": int(adReadKept / time.Minute),
		"plan": s.adPlan(rd, adimport.Mapping{})}, nil
}

type adChoices struct {
	ID string `json:"id"`
	adimport.Mapping
}

func (s *Server) postADPreview(r *http.Request) (any, error) {
	var req adChoices
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	rd, err := s.adGet(req.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"plan": s.adPlan(rd, req.Mapping)}, nil
}

// adFeatures: the names and employee values of a row, for the modules that are on. A value
// keelAuth's rules refuse (an employee number of the wrong length, one already given) is
// left out and said: the account matters more.
func (s *Server) adFeatures(row adimport.Row) (map[string]json.RawMessage, []string) {
	out := map[string]json.RawMessage{}
	var notes []string
	put := func(module string, v map[string]string) {
		f := findFeature(module)
		if len(v) == 0 || f == nil || !s.moduleOn(module) {
			return
		}
		raw, _ := json.Marshal(v)
		if _, err := s.normalizeFeature(f, row.Name, raw); err != nil {
			notes = append(notes, module+" not taken over: "+err.Error())
			return
		}
		out[module] = raw
	}
	names := map[string]string{}
	for k, v := range map[string]string{"sn": row.Sn, "givenName": row.GivenName, "phoneticLastName": row.PhoneticLast, "phoneticFirstName": row.PhoneticFirst} {
		if v != "" {
			names[k] = v
		}
	}
	put("names", names)
	if row.EmployeeNumber != "" {
		put("employee", map[string]string{"employeeNumber": row.EmployeeNumber})
	}
	return out, notes
}

// adMailGroup: how a mailbox at domain comes about: ticked (group ""), by membership of a
// group, or for every account ("*").
func (s *Server) adMailGroup(domain string) string {
	st := s.State()
	for _, k := range st.SyncKeys {
		if slices.Contains(k.MailDomains, domain) {
			return st.ServiceGroups[accessSync+k.ID]
		}
	}
	return ""
}

func (s *Server) postADRun(r *http.Request) (any, error) {
	var req adChoices
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	rd, err := s.adGet(req.ID)
	if err != nil {
		return nil, err
	}
	p := s.adPlan(rd, req.Mapping)
	type failure struct {
		AD    string `json:"ad"`
		Name  string `json:"name"`
		Error string `json:"error"`
	}
	failed := []failure{}
	madeGroups := []string{}
	groupOK := map[string]bool{} // keelAuth groups that are there now
	for _, g := range p.Groups {
		if !g.Ticked || g.Problem != "" {
			continue
		}
		if !g.Exists {
			desc := ""
			for _, ag := range rd.dir.Groups {
				if ag.Name == g.AD {
					desc = ag.Description
				}
			}
			if _, err := s.Eng.CreateGroup(g.Name, desc); err != nil {
				failed = append(failed, failure{g.AD, g.Name, "group: " + err.Error()})
				continue
			}
			madeGroups = append(madeGroups, g.Name)
		}
		groupOK[g.Name] = true
	}

	made := []adMade{}
	notes := map[string][]string{}
	yes := true
	for _, row := range p.Rows {
		if !row.Ticked || row.Problem != "" {
			continue
		}
		nu := newUser{Name: row.Name, DisplayName: row.DisplayName, Mail: row.Contact, MustChange: &yes}
		for _, g := range row.NewGroups {
			if groupOK[g] {
				nu.Groups = append(nu.Groups, g)
			}
		}
		for _, dom := range row.MailDomains {
			switch g := s.adMailGroup(dom); {
			case g == "":
				nu.MailDomains = append(nu.MailDomains, dom)
			case g != everyAccount && !slices.Contains(nu.Groups, g):
				if s.checkGroups([]string{g}) == nil {
					nu.Groups = append(nu.Groups, g)
				} else {
					notes[row.Name] = append(notes[row.Name], "no mailbox yet: the mail server's group "+g+" does not exist")
				}
			}
		}
		var fnotes []string
		nu.Features, fnotes = s.adFeatures(row)
		if len(fnotes) > 0 {
			notes[row.Name] = append(notes[row.Name], fnotes...)
		}
		o, err := s.makeUser(nu)
		if err != nil {
			failed = append(failed, failure{row.Sam, row.Name, err.Error()})
			delete(notes, row.Name)
			continue
		}
		if row.Disabled {
			if err := s.Eng.SetEnabled(row.Name, false); err != nil {
				notes[row.Name] = append(notes[row.Name], "could not be disabled: "+err.Error())
			}
		}
		made = append(made, adMade{Name: o.Name, DisplayName: o.DisplayName, Mail: o.Mail, Addresses: o.Addresses, Password: o.Password})
	}

	// People keelAuth already had go into the groups too (a second run after more groups were ticked).
	for _, g := range p.Groups {
		if !groupOK[g.Name] {
			continue
		}
		eg, err := s.lookupGroup(g.Name)
		if err != nil {
			continue
		}
		members := slices.Clone(eg.Members)
		for _, m := range g.Members {
			if u, _ := s.Eng.User(m); u != nil && !slices.Contains(members, m) {
				members = append(members, m)
			}
		}
		if len(members) != len(eg.Members) {
			if err := s.setMembers(eg, members); err != nil {
				failed = append(failed, failure{g.AD, g.Name, "group members: " + err.Error()})
			}
		}
	}
	if len(made) > 0 || len(madeGroups) > 0 {
		s.radiusLater()
	}
	s.adMu.Lock()
	rd.made = append(rd.made, made...)
	s.adMu.Unlock()
	who := ""
	if c := caller(r); c != nil {
		who = c.Name
	}
	s.Log.Printf("AD import by %s from %s: %d accounts and %d groups made, %d failed", who, rd.dir.Domain, len(made), len(madeGroups), len(failed))

	// What is left: the same choices without the rows just made (they are "exists" now).
	left := req.Mapping
	if left.Users != nil {
		done := map[string]bool{}
		for _, m := range made {
			done[m.Name] = true
		}
		var keep []string
		for _, row := range p.Rows {
			if row.Ticked && !done[row.Name] {
				keep = append(keep, row.Sam)
			}
		}
		left.Users = append([]string{}, keep...)
	}
	return map[string]any{"made": made, "groups": madeGroups, "failed": failed, "notes": notes, "plan": s.adPlan(rd, left)}, nil
}

// getADPasswords: every account made from this read with its initial password, as CSV. The
// table lives as long as the read does (memory only, until 15 minutes without use).
func (s *Server) getADPasswords(w http.ResponseWriter, r *http.Request) {
	rd, err := s.adGet(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error(), "code": "ad_read_gone"})
		return
	}
	s.adMu.Lock()
	made := slices.Clone(rd.made)
	s.adMu.Unlock()
	var buf bytes.Buffer
	buf.WriteString("\xef\xbb\xbf") // so that Excel reads it as UTF-8
	cw := csv.NewWriter(&buf)
	cw.UseCRLF = true
	cw.Write([]string{"account", "name", "mail", "initial password"})
	for _, m := range made {
		mail := strings.Join(m.Addresses, " ")
		if mail == "" {
			mail = m.Mail
		}
		cw.Write([]string{m.Name, m.DisplayName, mail, m.Password})
	}
	cw.Flush()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="keelauth-initial-passwords.csv"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}
