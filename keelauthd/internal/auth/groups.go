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
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Members     []string `json:"members"`
	GID         int      `json:"gid"`
	Builtin     bool     `json:"builtin"`
}

func groupOut(g *engine.Group) GroupOut {
	m := slices.DeleteFunc(slices.Clone(g.Members), func(x string) bool { return x == BindAccount })
	if m == nil {
		m = []string{}
	}
	return GroupOut{Name: g.Name, Description: g.Description, Members: m, GID: g.GID, Builtin: g.Name == AdminGroup}
}

func (s *Server) getGroups(r *http.Request) (any, error) {
	gs, err := s.Eng.Groups()
	if err != nil {
		return nil, err
	}
	out := []GroupOut{}
	for i := range gs {
		out = append(out, groupOut(&gs[i]))
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
	if err := s.checkUsers(members); err != nil {
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
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	switch {
	case !ValidName(req.Name):
		return nil, bad("group name %q: lower-case letters, digits, - and _, a letter first, at most 32", req.Name)
	case reserved(req.Name):
		return nil, conflict("the name %q is reserved", req.Name)
	}
	if err := s.checkUsers(req.Members); err != nil {
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
	return groupOut(g), nil
}

func (s *Server) patchGroup(r *http.Request) (any, error) {
	g, err := s.lookupGroup(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Description *string   `json:"description"`
		Members     *[]string `json:"members"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
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
	return groupOut(g), nil
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
	m := slices.DeleteFunc(slices.Clone(g.Members), func(x string) bool { return slices.Contains(req.Remove, x) })
	m = append(m, req.Add...)
	sort.Strings(m)
	if err := s.setMembers(g, m); err != nil {
		return nil, err
	}
	if g, err = s.lookupGroup(g.Name); err != nil {
		return nil, err
	}
	return groupOut(g), nil
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
	s.bump()
	return map[string]any{}, nil
}
