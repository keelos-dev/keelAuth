// Package adimport moves the accounts of a Windows Active Directory into keelAuth once
// (docs/07): Read takes people and groups out of the directory, Map turns them into what
// keelAuth would hold under the administrator's choices. Nothing here writes anywhere: the
// caller (internal/auth) makes the accounts from the Plan.
package adimport

import (
	"fmt"
	"sort"
	"strings"

	"keelauth/internal/module/ldap"
)

// Person is one AD user account.
type Person struct {
	Sam            string   `json:"sam"` // sAMAccountName, as AD spells it
	UPN            string   `json:"upn"`
	DisplayName    string   `json:"display_name"`
	Mail           string   `json:"mail"`
	Aliases        []string `json:"aliases"` // further addresses (proxyAddresses): shown, not imported
	Sn             string   `json:"sn"`
	GivenName      string   `json:"given_name"`
	PhoneticLast   string   `json:"phonetic_last_name"`
	PhoneticFirst  string   `json:"phonetic_first_name"`
	EmployeeNumber string   `json:"employee_number"`
	Disabled       bool     `json:"disabled"`
	Groups         []string `json:"groups"` // AD group names, groups inside groups followed
}

// Group is one AD group.
type Group struct {
	Name        string `json:"name"` // sAMAccountName
	Description string `json:"description"`
}

// Directory is what was read.
type Directory struct {
	Domain string   `json:"domain"` // ad.example.com
	People []Person `json:"users"`
	Groups []Group  `json:"groups"`
}

// MailDomains is the domains of the people's addresses, lower case, sorted.
func (d *Directory) MailDomains() []string {
	seen := map[string]bool{}
	for _, p := range d.People {
		if _, dom := splitMail(p.Mail); dom != "" {
			seen[dom] = true
		}
	}
	out := make([]string, 0, len(seen))
	for dom := range seen {
		out = append(out, dom)
	}
	sort.Strings(out)
	return out
}

func splitMail(addr string) (local, domain string) {
	i := strings.LastIndexByte(addr, '@')
	if i <= 0 || i == len(addr)-1 {
		return "", ""
	}
	return addr[:i], strings.ToLower(addr[i+1:])
}

// Searcher is the part of *ldap.Upstream Read uses.
type Searcher interface {
	Search(base string, baseOnly bool, filter ldap.Filter, attrs []string, each func(ldap.Entry) error) error
}

// Read takes the people and groups out of a bound connection. System accounts and groups
// (Administrator, krbtgt, Domain Users, everything under Builtin) and computers are left out.
func Read(u Searcher) (*Directory, error) {
	base := ""
	err := u.Search("", true, ldap.Present("objectClass"), []string{"defaultNamingContext"}, func(e ldap.Entry) error {
		base = e.First("defaultNamingContext")
		return nil
	})
	if err != nil {
		return nil, err
	}
	if base == "" {
		return nil, fmt.Errorf("the directory does not say where its domain starts (no defaultNamingContext): is this an Active Directory?")
	}
	d := &Directory{Domain: domainOf(base)}

	system := func(e ldap.Entry) bool {
		return strings.EqualFold(e.First("isCriticalSystemObject"), "TRUE") || strings.Contains(strings.ToLower(e.DN), ",cn=builtin,")
	}
	groupByDN := map[string]string{} // lower-case DN -> name
	parents := map[string][]string{} // lower-case DN of a group -> DNs of the groups it is in
	err = u.Search(base, false, ldap.Eq("objectCategory", "group"),
		[]string{"sAMAccountName", "description", "memberOf", "isCriticalSystemObject"}, func(e ldap.Entry) error {
			name := e.First("sAMAccountName")
			if name == "" || system(e) {
				return nil
			}
			dn := strings.ToLower(e.DN)
			groupByDN[dn] = name
			parents[dn] = e.Attrs["memberof"]
			d.Groups = append(d.Groups, Group{Name: name, Description: e.First("description")})
			return nil
		})
	if err != nil {
		return nil, err
	}
	// groupsOf: the names of the groups reached from these memberOf values, parents included.
	groupsOf := func(memberOf []string) []string {
		seen := map[string]bool{}
		var walk func(dns []string)
		walk = func(dns []string) {
			for _, dn := range dns {
				dn = strings.ToLower(dn)
				if _, ok := groupByDN[dn]; !ok || seen[dn] {
					continue
				}
				seen[dn] = true
				walk(parents[dn])
			}
		}
		walk(memberOf)
		out := make([]string, 0, len(seen))
		for dn := range seen {
			out = append(out, groupByDN[dn])
		}
		sort.Strings(out)
		return out
	}

	err = u.Search(base, false, ldap.And(ldap.Eq("objectCategory", "person"), ldap.Eq("objectClass", "user")),
		[]string{"sAMAccountName", "userPrincipalName", "displayName", "mail", "proxyAddresses", "sn", "givenName",
			"msDS-PhoneticLastName", "msDS-PhoneticFirstName", "employeeNumber", "employeeID", "userAccountControl",
			"memberOf", "isCriticalSystemObject"}, func(e ldap.Entry) error {
			sam := e.First("sAMAccountName")
			if sam == "" || system(e) || strings.HasSuffix(sam, "$") {
				return nil
			}
			p := Person{Sam: sam, UPN: e.First("userPrincipalName"), DisplayName: e.First("displayName"), Mail: e.First("mail"),
				Sn: e.First("sn"), GivenName: e.First("givenName"),
				PhoneticLast: e.First("msDS-PhoneticLastName"), PhoneticFirst: e.First("msDS-PhoneticFirstName"),
				EmployeeNumber: e.First("employeeNumber"), Groups: groupsOf(e.Attrs["memberof"])}
			if p.EmployeeNumber == "" {
				p.EmployeeNumber = e.First("employeeID")
			}
			var uac int
			fmt.Sscanf(e.First("userAccountControl"), "%d", &uac)
			p.Disabled = uac&2 != 0
			for _, a := range e.Attrs["proxyaddresses"] { // "SMTP:main@x" is the main one, "smtp:other@x" an alias
				if len(a) > 5 && strings.EqualFold(a[:5], "smtp:") && !strings.EqualFold(a[5:], p.Mail) {
					p.Aliases = append(p.Aliases, a[5:])
				}
			}
			d.People = append(d.People, p)
			return nil
		})
	if err != nil {
		return nil, err
	}
	sort.Slice(d.People, func(i, j int) bool { return strings.ToLower(d.People[i].Sam) < strings.ToLower(d.People[j].Sam) })
	sort.Slice(d.Groups, func(i, j int) bool { return strings.ToLower(d.Groups[i].Name) < strings.ToLower(d.Groups[j].Name) })
	return d, nil
}

// domainOf: "DC=ad,DC=example,DC=com" -> "ad.example.com".
func domainOf(dn string) string {
	var parts []string
	for _, rdn := range strings.Split(dn, ",") {
		if kv := strings.SplitN(strings.TrimSpace(rdn), "=", 2); len(kv) == 2 && strings.EqualFold(kv[0], "DC") {
			parts = append(parts, strings.ToLower(kv[1]))
		}
	}
	return strings.Join(parts, ".")
}

// Mapping is the administrator's choices (docs/07 §3). The zero value is the defaults.
type Mapping struct {
	NameFrom string              `json:"name_from"` // "sam" (default), "mail", "upn"
	Rename   map[string]string   `json:"rename"`    // AD account name -> the name typed for it
	Mail     map[string]MailRule `json:"mail"`      // domain of the AD address -> what becomes of it
	Users    []string            `json:"users"`     // the ticked AD account names; nil = the default ticks
	Groups   map[string]string   `json:"groups"`    // the ticked AD groups -> name typed ("" = converted); nil = default
}

// MailRule: To is "domain" (a mailbox <name>@Domain with us), "keep" (the address stays the
// account's contact address) or "drop".
type MailRule struct {
	To     string `json:"to"`
	Domain string `json:"domain,omitempty"`
}

// Env is what Map needs to know of keelAuth.
type Env struct {
	HaveUser    func(name string) bool
	HaveGroup   func(name string) bool
	ValidUser   func(name string) bool
	ValidGroup  func(name string) bool
	MailDomains []string // the domains the mail server offers
}

// Row is one AD person as keelAuth would hold them.
type Row struct {
	Person
	Name        string   `json:"name"`         // the keelAuth account name
	Ticked      bool     `json:"ticked"`       // to be imported
	Exists      bool     `json:"exists"`       // keelAuth has this name already: never imported
	Contact     string   `json:"contact"`      // the account's own (contact) address
	MailDomains []string `json:"mail_domains"` // our mail domains the person gets a mailbox in
	Addresses   []string `json:"addresses"`    // those mailboxes
	NewGroups   []string `json:"new_groups"`   // keelAuth groups the person goes into
	Notes       []Note   `json:"notes"`        // worth knowing, not in the way
	Problem     string   `json:"problem"`      // in the way: the import is refused while a ticked row has one
	ProblemCode string   `json:"problem_code"` // the same, for a page that words it itself
}

// Note is something worth knowing about a row: Text in English, Code and Args for a page
// that words it in its own language.
type Note struct {
	Code string   `json:"code"`
	Args []string `json:"args"`
	Text string   `json:"text"`
}

func (r *Row) note(code, text string, args ...string) {
	r.Notes = append(r.Notes, Note{Code: code, Args: args, Text: text})
}

// problem keeps the first thing in the way.
func (r *Row) problem(code, text string) {
	if r.Problem == "" {
		r.Problem, r.ProblemCode = text, code
	}
}

// SetProblem marks the group (the first problem stays).
func (g *GroupRow) SetProblem(code, text string) {
	if g.Problem == "" {
		g.Problem, g.ProblemCode = text, code
	}
}

// GroupRow is one AD group as keelAuth would hold it.
type GroupRow struct {
	AD          string   `json:"ad"`
	Name        string   `json:"name"`
	Ticked      bool     `json:"ticked"`
	Exists      bool     `json:"exists"` // keelAuth has a group of this name: the people are added to it
	Members     []string `json:"members"`
	Problem     string   `json:"problem"`
	ProblemCode string   `json:"problem_code"`
}

// Plan is the whole import as it would happen.
type Plan struct {
	Rows     []Row               `json:"users"`
	Groups   []GroupRow          `json:"groups"`
	Mail     map[string]MailRule `json:"mail"`     // the rule in force for every domain seen
	Problems int                 `json:"problems"` // ticked rows and groups with a problem
}

// GroupName is an AD group name as a keelAuth one: lower case, anything but a-z 0-9 _ -
// becomes "-". "" when nothing usable is left (a name in kana, say).
func GroupName(ad string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(ad) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	n := strings.Trim(b.String(), "-")
	for strings.Contains(n, "--") {
		n = strings.ReplaceAll(n, "--", "-")
	}
	if len(n) > 32 {
		n = strings.TrimRight(n[:32], "-")
	}
	return n
}

// Map applies m to d.
func Map(d *Directory, m Mapping, env Env) *Plan {
	p := &Plan{Mail: map[string]MailRule{}}
	offered := map[string]bool{}
	for _, dom := range env.MailDomains {
		offered[strings.ToLower(dom)] = true
	}
	for _, dom := range d.MailDomains() {
		r, ok := m.Mail[dom]
		if !ok {
			if offered[dom] {
				r = MailRule{To: "domain", Domain: dom}
			} else {
				r = MailRule{To: "keep"}
			}
		}
		r.Domain = strings.ToLower(r.Domain)
		p.Mail[dom] = r
	}
	var ticked map[string]bool
	if m.Users != nil {
		ticked = map[string]bool{}
		for _, s := range m.Users {
			ticked[s] = true
		}
	}

	byName := map[string][]int{} // account name -> ticked rows wanting it
	for _, person := range d.People {
		r := Row{Person: person}
		switch typed := strings.TrimSpace(m.Rename[person.Sam]); {
		case typed != "":
			r.Name = typed
		case m.NameFrom == "mail":
			if local, _ := splitMail(person.Mail); local != "" {
				r.Name = strings.ToLower(local)
			} else {
				r.Name = strings.ToLower(person.Sam)
				r.note("no_mail", "no mail address: the AD account name is used")
			}
		case m.NameFrom == "upn":
			if local, _ := splitMail(person.UPN); local != "" {
				r.Name = strings.ToLower(local)
			} else {
				r.Name = strings.ToLower(person.Sam)
				r.note("no_upn", "no login name (UPN): the AD account name is used")
			}
		default:
			r.Name = strings.ToLower(person.Sam)
		}
		r.Exists = env.HaveUser(r.Name)
		if ticked == nil {
			r.Ticked = !person.Disabled && !r.Exists
		} else {
			r.Ticked = ticked[person.Sam]
		}
		switch {
		case !env.ValidUser(r.Name):
			r.problem("name_invalid", "not a name keelAuth takes: a letter first, then a-z 0-9 - _ and single dots, 32 at most")
		case r.Exists && r.Ticked:
			r.problem("exists", "keelAuth already has an account of this name")
		}

		if local, dom := splitMail(person.Mail); dom != "" {
			switch rule := p.Mail[dom]; rule.To {
			case "domain":
				if !offered[rule.Domain] {
					r.problem("mail_domain", "the mail server has no domain "+rule.Domain)
					break
				}
				r.MailDomains = []string{rule.Domain}
				addr := r.Name + "@" + rule.Domain
				r.Addresses = []string{addr}
				// said only when the part before @ changes: a domain mapped to another is the
				// administrator's own choice, on every row it would only be noise
				if !strings.EqualFold(local, r.Name) {
					r.note("address_changes", "address changes: "+person.Mail+" -> "+addr, person.Mail, addr)
				}
			case "keep":
				r.Contact = person.Mail
			case "drop":
			default:
				r.problem("mail_rule", "no such choice for mail of "+dom+": "+rule.To)
			}
		}
		if len(person.Aliases) > 0 {
			r.note("aliases", "further addresses are not imported: "+strings.Join(person.Aliases, ", "), strings.Join(person.Aliases, ", "))
		}
		if person.Disabled && r.Ticked {
			r.note("disabled", "disabled in AD: imported as a disabled account")
		}
		p.Rows = append(p.Rows, r)
		if r.Ticked {
			byName[r.Name] = append(byName[r.Name], len(p.Rows)-1)
		}
	}
	for name, rows := range byName {
		if len(rows) < 2 {
			continue
		}
		for _, i := range rows {
			p.Rows[i].problem("duplicate", fmt.Sprintf("%d ticked people would all be %s", len(rows), name))
		}
	}

	// Groups: members are the ticked people and those keelAuth already has.
	members := map[string][]string{}
	for _, r := range p.Rows {
		if (r.Ticked && r.Problem == "") || (r.Exists && !r.Ticked) {
			for _, g := range r.Groups {
				members[g] = append(members[g], r.Name)
			}
		}
	}
	newName := map[string]string{} // AD group -> keelAuth group, ticked and sound ones
	taken := map[string]string{}
	for _, g := range d.Groups {
		gr := GroupRow{AD: g.Name, Members: members[g.Name]}
		sort.Strings(gr.Members)
		typed, isTicked := m.Groups[g.Name]
		if m.Groups == nil {
			isTicked = len(gr.Members) > 0
		}
		if gr.Name = strings.TrimSpace(typed); gr.Name == "" {
			gr.Name = GroupName(g.Name)
		}
		gr.Ticked = isTicked
		gr.Exists = gr.Name != "" && env.HaveGroup(gr.Name)
		switch {
		case gr.Name == "":
			gr.SetProblem("group_name", "needs a name: keelAuth group names are a-z 0-9 - _")
		case !env.ValidGroup(gr.Name):
			gr.SetProblem("group_invalid", "not a group name keelAuth takes: a letter first, then a-z 0-9 - _")
		case gr.Ticked && taken[gr.Name] != "":
			gr.SetProblem("group_duplicate", "same name as the group made from "+taken[gr.Name])
		}
		if gr.Ticked && gr.Problem == "" {
			taken[gr.Name] = g.Name
			newName[g.Name] = gr.Name
		}
		if gr.Ticked && gr.Problem != "" {
			p.Problems++
		}
		p.Groups = append(p.Groups, gr)
	}
	for i := range p.Rows {
		r := &p.Rows[i]
		for _, g := range r.Groups {
			if n := newName[g]; n != "" {
				r.NewGroups = append(r.NewGroups, n)
			}
		}
		sort.Strings(r.NewGroups)
		if r.Ticked && r.Problem != "" {
			p.Problems++
		}
	}
	return p
}
