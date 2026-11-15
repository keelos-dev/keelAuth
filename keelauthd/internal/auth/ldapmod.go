package auth

import (
	"crypto/tls"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"keelauth/internal/engine"
	"keelauth/internal/module/ldap"
)

// The ldap module (docs/01 "2026-10-30 晚", 模块化): with the native engine keelauthd serves
// LDAPS itself on the LDAP port, from the account store, through internal/module/ldap. With
// Kanidm, Kanidm's LDAP serves and this is off.

// ldapDir is the account store as the LDAP module reads it.
type ldapDir struct{ s *Server }

func (d ldapDir) BaseDN() string { return BaseDN(d.s.State().Domain) }
func (d ldapDir) Domain() string { return d.s.State().Domain }

// flat is the groups with nested membership flattened: each group's persons, and each
// person's groups.
func (d ldapDir) flat() (groups []engine.Group, members map[string][]string, memberOf map[string][]string) {
	gs, err := d.s.Eng.Groups()
	if err != nil {
		return nil, nil, nil
	}
	byName := map[string]*engine.Group{}
	for i := range gs {
		byName[gs[i].Name] = &gs[i]
	}
	members = map[string][]string{}
	var persons func(g *engine.Group, seen map[string]bool) []string
	persons = func(g *engine.Group, seen map[string]bool) []string {
		if seen[g.Name] {
			return nil
		}
		seen[g.Name] = true
		out := append([]string(nil), g.Members...)
		for _, sub := range g.MemberGroups {
			if sg := byName[sub]; sg != nil {
				out = append(out, persons(sg, seen)...)
			}
		}
		return out
	}
	memberOf = map[string][]string{}
	for i := range gs {
		ms := persons(&gs[i], map[string]bool{})
		sort.Strings(ms)
		ms = dedup(ms)
		members[gs[i].Name] = ms
		for _, m := range ms {
			memberOf[m] = append(memberOf[m], gs[i].Name)
		}
	}
	return gs, members, memberOf
}

func dedup(xs []string) []string {
	out := xs[:0]
	for i, x := range xs {
		if i == 0 || x != xs[i-1] {
			out = append(out, x)
		}
	}
	return out
}

// People: the accounts that have LDAP.
func (d ldapDir) People() []ldap.Person { return d.people(AccessLDAP, "") }

// PeopleSeenBy: what a bound connection finds. A device account that stands for a service
// (Device.Service: a mail server's) finds the accounts that have that service. A person
// who has LDAP, and keelAuth's shared bind account, find those who have LDAP. A person who
// may bind only through a device's service (ldapServices) finds himself alone: his password
// was checked, the directory is not his to read.
func (d ldapDir) PeopleSeenBy(bound string) []ldap.Person {
	if dev, ok := strings.CutPrefix(bound, "device:"); ok {
		if x := d.s.State().device(dev); x != nil && x.Service != "" {
			return d.people(x.Service, "")
		}
		return d.people(AccessLDAP, "")
	}
	if bound == BindAccount || d.s.allowed(bound, AccessLDAP) {
		return d.people(AccessLDAP, "")
	}
	return d.people("", bound)
}

// ldapServices: LDAP itself and every service a device account stands for: an account with
// one of them may bind with its password.
func ldapServices(st *State) []string {
	out := []string{AccessLDAP}
	for _, x := range st.Devices {
		if x.Service != "" && !slices.Contains(out, x.Service) {
			out = append(out, x.Service)
		}
	}
	return out
}

// people: the enabled accounts that have the service, or (only != "") that one account.
func (d ldapDir) people(service, only string) []ldap.Person {
	us, err := d.s.Eng.Users()
	if err != nil {
		return nil
	}
	_, _, memberOf := d.flat()
	ac := accessChecker{st: d.s.State(), memberOf: memberOf, open: d.s.openUnbound}
	out := []ldap.Person{}
	for _, u := range us {
		if !u.Enabled || u.Name == BindAccount {
			continue
		}
		if only != "" && u.Name != only || only == "" && !ac.allowed(u.Name, service) {
			continue
		}
		p := ldap.Person{Name: u.Name, DisplayName: u.DisplayName, UID: u.UID, UUID: u.UUID, Groups: memberOf[u.Name]}
		if p.Groups == nil {
			p.Groups = []string{}
		}
		if u.Mail != "" {
			p.Mails = []string{u.Mail}
		}
		p.Mails = append(p.Mails, ac.addresses(u.Name)...)
		p.Extra = d.s.ldapExtras(u.Name)
		out = append(out, p)
	}
	return out
}

func (d ldapDir) Groups() []ldap.Group {
	gs, members, _ := d.flat()
	out := []ldap.Group{}
	for _, g := range gs {
		out = append(out, ldap.Group{Name: g.Name, Description: g.Description, Members: members[g.Name], GID: g.GID})
	}
	return out
}

// Reads: the feature modules a device account's bind sees the attributes of.
func (d ldapDir) Reads(device string) []string {
	if x := d.s.State().device(device); x != nil {
		return x.Features
	}
	return nil
}

func (d ldapDir) CheckPassword(name, pw string) bool {
	if name != BindAccount {
		ac := d.s.accessChecker()
		if !slices.ContainsFunc(ldapServices(ac.st), func(svc string) bool { return ac.allowed(name, svc) }) {
			return false
		}
	}
	ok, err := d.s.Eng.CheckPassword(name, pw)
	return err == nil && ok
}

func (d ldapDir) CheckToken(token string) (string, bool) {
	if n := d.s.native(); n != nil {
		return n.FindToken(token)
	}
	return "", false
}

// ldapListening: the module's listener is up (status, alerts).
var ldapListening atomic.Bool

// serveLDAP runs the ldap module on the LDAP port over TLS (the same certificate as the web
// page), trying again every 5 s when the port cannot be taken.
func (s *Server) serveLDAP(port int) {
	srv := &ldap.Server{Dir: ldapDir{s}, Log: s.Log}
	tc := &tls.Config{GetCertificate: s.serverCert, MinVersion: tls.VersionTLS12}
	addr := fmt.Sprintf(":%d", port)
	for i := 0; ; i++ {
		if !s.moduleOn("ldap") { // switched off (modules.go): wait for the switch
			time.Sleep(2 * time.Second)
			continue
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if i%12 == 0 {
				s.Log.Printf("ldap: listen %s: %v (trying again every 5 s)", addr, err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		s.Log.Printf("ldap: listening on %s (LDAPS)", addr)
		s.setModuleCloser("ldap", ln)
		ldapListening.Store(true)
		err = srv.Serve(tls.NewListener(ln, tc))
		ldapListening.Store(false)
		s.setModuleCloser("ldap", nil)
		if !s.moduleOn("ldap") {
			s.Log.Printf("ldap: stopped (module off)")
			continue
		}
		s.Log.Printf("ldap: %v", err)
		time.Sleep(5 * time.Second)
	}
}
