package auth

import (
	"errors"
	"net/http"
	"slices"
	"sort"

	"keelauth/internal/engine"
)

// GroupOut is a group in the API.
type GroupOut struct {
	Name         string   `json:"name"`
	Description  string   `json:"description"`
	Members      []string `json:"members"`
	MemberGroups []string `json:"member_groups"`
	GID          int      `json:"gid"`
	Builtin      bool     `json:"builtin"`
	Access       []string `json:"access"` // the services its members may use (added to their own)
}

// groupView is groupOut with what keelauthd keeps of the group (the access list).
func (s *Server) groupView(g *engine.Group) GroupOut {
	o := groupOut(g)
	o.Access = []string{}
	if gd := s.State().Groups[g.Name]; gd != nil && gd.Access != nil {
		o.Access = gd.Access
	}
	return o
}

func groupOut(g *engine.Group) GroupOut {
	m := slices.DeleteFunc(slices.Clone(g.Members), func(x string) bool { return x == BindAccount })
	if m == nil {
		m = []string{}
	}
	mg := slices.Clone(g.MemberGroups)
	if mg == nil {
		mg = []string{}
	}
	return GroupOut{Name: g.Name, Description: g.Description, Members: m, MemberGroups: mg, GID: g.GID, Builtin: g.Name == AdminGroup}
}

func (s *Server) getGroups(r *http.Request) (any, error) {
	gs, err := s.Eng.Groups()
	if err != nil {
		return nil, err
	}
	out := []GroupOut{}
	for i := range gs {
		out = append(out, s.groupView(&gs[i]))
	}
	return map[string]any{"groups": out}, nil
}

func (s *Server) lookupGroup(name string) (*engine.Group, error) {
	g, err := s.Eng.Group(name)
	if errors.Is(err, engine.ErrNotFound) {
		return nil, notFound("no group %q", name)
	}
	return g, err
}

// checkMembers: every name is a user or an existing group; self is the group being
// changed ("" for a new one). A group cannot be its own member or form a direct cycle.
func (s *Server) checkMembers(self string, names []string) error {
	var gs []engine.Group
	for _, n := range names {
		if gs == nil {
			var err error
			if gs, err = s.Eng.Groups(); err != nil {
				return err
			}
		}
		i := slices.IndexFunc(gs, func(g engine.Group) bool { return g.Name == n })
		if i < 0 {
			if err := s.checkUsers([]string{n}); err != nil {
				return err
			}
			continue
		}
		switch {
		case n == self:
			return bad("group %q cannot be a member of itself", n)
		case self == AdminGroup:
			return bad("group %q cannot be a member of %s: only users", n, AdminGroup)
		case slices.Contains(gs[i].MemberGroups, self):
			return bad("group %q already has %q as a member: that would be a cycle", n, self)
		}
	}
	return nil
}

// checkUsers: every name is a user.
func (s *Server) checkUsers(names []string) error {
	for _, n := range names {
		if _, err := s.lookupUser(n); err != nil {
			if errors.Is(err, engine.ErrNotFound) || isNotFound(err) {
				return bad("no user %q", n)
			}
			return err
		}
	}
	return nil
}

func isNotFound(err error) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// setMembers sets a group's members, guarding the last admin.
func (s *Server) setMembers(g *engine.Group, members []string) error {
	members = slices.Compact(slices.Sorted(slices.Values(members)))
	if err := s.checkMembers(g.Name, members); err != nil {
		return err
	}
	if g.Name == AdminGroup {
		for _, m := range g.Members {
			if !slices.Contains(members, m) {
				if err := s.lastAdmin(m, true); err != nil {
					return err
				}
				s.sessions.dropUser(m)
			}
		}
	}
	if err := s.Eng.SetMembers(g.Name, members); err != nil {
		return err
	}
	s.bump()
	if g.Name == s.State().Radius.Group {
		s.radiusLater()
	}
	return nil
}

func (s *Server) postGroup(r *http.Request) (any, error) {
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Members     []string `json:"members"`
		Access      []string `json:"access"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if err := s.checkAccess(req.Access); err != nil {
		return nil, err
	}
	switch {
	case !ValidName(req.Name):
		return nil, bad("group name %q: lower-case letters, digits, - and _, a letter first, at most 32", req.Name)
	case reserved(req.Name):
		return nil, conflict("the name %q is reserved", req.Name)
	}
	if err := s.checkMembers("", req.Members); err != nil {
		return nil, err
	}
	g, err := s.Eng.CreateGroup(req.Name, req.Description)
	if errors.Is(err, engine.ErrExists) {
		return nil, conflict("the name %q is taken (a user or a group)", req.Name)
	}
	if err != nil {
		return nil, err
	}
	if len(req.Members) > 0 {
		if err := s.setMembers(g, req.Members); err != nil {
			return nil, err
		}
	} else {
		s.bump()
	}
	if g, err = s.lookupGroup(req.Name); err != nil {
		return nil, err
	}
	if len(req.Access) > 0 {
		if err := s.update(func(st *State) error { st.Groups[g.Name] = &GroupData{Access: cleanAccess(req.Access)}; return nil }, true); err != nil {
			return nil, err
		}
	}
	return s.groupView(g), nil
}

func (s *Server) patchGroup(r *http.Request) (any, error) {
	g, err := s.lookupGroup(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Description *string   `json:"description"`
		Members     *[]string `json:"members"`
		Access      *[]string `json:"access"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if req.Access != nil {
		if err := s.checkAccess(*req.Access); err != nil {
			return nil, err
		}
		if err := s.update(func(st *State) error {
			st.Groups[g.Name] = &GroupData{Access: cleanAccess(*req.Access)}
			return nil
		}, true); err != nil {
			return nil, err
		}
		s.radiusLater()
	}
	if req.Description != nil {
		if err := s.Eng.UpdateGroup(g.Name, req.Description); err != nil {
			return nil, err
		}
	}
	if req.Members != nil {
		if err := s.setMembers(g, *req.Members); err != nil {
			return nil, err
		}
	}
	if g, err = s.lookupGroup(g.Name); err != nil {
		return nil, err
	}
	return s.groupView(g), nil
}

func (s *Server) postMembers(r *http.Request) (any, error) {
	g, err := s.lookupGroup(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	m := slices.DeleteFunc(append(slices.Clone(g.Members), g.MemberGroups...), func(x string) bool { return slices.Contains(req.Remove, x) })
	m = append(m, req.Add...)
	sort.Strings(m)
	if err := s.setMembers(g, m); err != nil {
		return nil, err
	}
	if g, err = s.lookupGroup(g.Name); err != nil {
		return nil, err
	}
	return s.groupView(g), nil
}

func (s *Server) deleteGroup(r *http.Request) (any, error) {
	g, err := s.lookupGroup(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	if g.Name == AdminGroup {
		return nil, conflict("%s cannot be deleted", AdminGroup)
	}
	if s.State().Radius.Group == g.Name {
		return nil, conflict("group %s decides who may use RADIUS: change that first", g.Name)
	}
	if err := s.Eng.DeleteGroup(g.Name); err != nil {
		return nil, err
	}
	s.update(func(st *State) error { delete(st.Groups, g.Name); return nil }, false)
	s.bump()
	return map[string]any{}, nil
}
