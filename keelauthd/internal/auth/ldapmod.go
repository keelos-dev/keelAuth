package auth

import (
	"crypto/tls"
	"fmt"
	"net"
	"sort"
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

func (d ldapDir) People() []ldap.Person {
	us, err := d.s.Eng.Users()
	if err != nil {
		return nil
	}
	_, _, memberOf := d.flat()
	ac := accessChecker{st: d.s.State(), memberOf: memberOf}
	out := []ldap.Person{}
	for _, u := range us {
		if !u.Enabled || u.Name == BindAccount || !ac.allowed(u.Name, AccessLDAP) {
			continue
		}
		p := ldap.Person{Name: u.Name, DisplayName: u.DisplayName, UID: u.UID, UUID: u.UUID, Groups: memberOf[u.Name]}
		if p.Groups == nil {
			p.Groups = []string{}
		}
		if u.Mail != "" {
			p.Mails = []string{u.Mail}
		}
		p.Mails = append(p.Mails, addressesOf(ac.st, u.Name)...)
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

func (d ldapDir) CheckPassword(name, pw string) bool {
	if name != BindAccount && !d.s.allowed(name, AccessLDAP) {
		return false
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
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			if i%12 == 0 {
				s.Log.Printf("ldap: listen %s: %v (trying again every 5 s)", addr, err)
			}
			time.Sleep(5 * time.Second)
			continue
		}
		s.Log.Printf("ldap: listening on %s (LDAPS)", addr)
		ldapListening.Store(true)
		err = srv.Serve(tls.NewListener(ln, tc))
		ldapListening.Store(false)
		s.Log.Printf("ldap: %v", err)
		time.Sleep(5 * time.Second)
	}
}
