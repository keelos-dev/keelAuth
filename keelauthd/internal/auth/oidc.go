package auth

import (
	"errors"
	"net/http"
	"net/url"
	"sort"

	"keelauth/internal/engine"
)

// SSO (OIDC): each application is a client in Kanidm; who may log in is a group (its scope
// map), "" = every user. The client id is the name; Kanidm requires PKCE (S256) unless it is
// turned off for an old application.

// DefaultScopes are what an application gets.
var DefaultScopes = []string{"email", "groups", "openid", "profile"}

// OIDCOut is an application in the API.
type OIDCOut struct {
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name"`
	LandingURL   string   `json:"landing_url"`
	RedirectURLs []string `json:"redirect_urls"`
	ScopeGroup   string   `json:"scope_group"` // "" = all users
	Scopes       []string `json:"scopes"`
	ClientID     string   `json:"client_id"`
	Discovery    string   `json:"discovery_url"`
	Issuer       string   `json:"issuer"`
	PKCE         bool     `json:"pkce"`
	// ShortUsername: preferred_username is "alice", not "alice@<domain>"
	ShortUsername bool `json:"short_username"`
	// Roles: what the application says its groups mean there (keelOS); RolesBy: who said it;
	// Missing: those groups keelAuth does not have
	Roles   map[string]string `json:"roles,omitempty"`
	RolesBy string            `json:"roles_by,omitempty"`
	Missing []string          `json:"missing_groups,omitempty"`
	Secret  string            `json:"client_secret,omitempty"`
}

func (s *Server) oidcOut(c *engine.OAuth2) OIDCOut {
	o := OIDCOut{Name: c.Name, DisplayName: c.DisplayName, LandingURL: c.LandingURL, RedirectURLs: c.RedirectURLs,
		ClientID: c.Name, PKCE: c.PKCE, ShortUsername: c.ShortName, Scopes: []string{}}
	if r, ok := s.State().OIDCRoles[c.Name]; ok && len(r.Roles) > 0 {
		o.Roles, o.RolesBy = r.Roles, r.By
		for g := range r.Roles {
			if grp, err := s.Eng.Group(g); err != nil || grp == nil {
				o.Missing = append(o.Missing, g)
			}
		}
		sort.Strings(o.Missing)
	}
	if o.RedirectURLs == nil {
		o.RedirectURLs = []string{}
	}
	groups := []string{}
	for g := range c.ScopeMaps {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	if len(groups) > 0 {
		g := groups[0]
		o.Scopes = c.ScopeMaps[g]
		if g != engine.AllPersons {
			o.ScopeGroup = g
		}
	}
	origin := Origin(s.State().Domain)
	o.Issuer = origin + "/oauth2/openid/" + c.Name
	o.Discovery = o.Issuer + "/.well-known/openid-configuration"
	return o
}

func (s *Server) getOIDC(r *http.Request) (any, error) {
	cs, err := s.Eng.OAuth2s()
	if err != nil {
		return nil, err
	}
	out := []OIDCOut{}
	for i := range cs {
		out = append(out, s.oidcOut(&cs[i]))
	}
	return map[string]any{"issuer_base": Origin(s.State().Domain) + "/oauth2/openid/", "clients": out}, nil
}

func (s *Server) lookupOIDC(name string) (*engine.OAuth2, error) {
	c, err := s.Eng.OAuth2(name)
	if errors.Is(err, engine.ErrNotFound) {
		return nil, notFound("no SSO application %q", name)
	}
	return c, err
}

func (s *Server) getOIDCOne(r *http.Request) (any, error) {
	c, err := s.lookupOIDC(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	return s.oidcOut(c), nil
}

func validURL(u string) bool {
	p, err := url.Parse(u)
	return err == nil && (p.Scheme == "https" || p.Scheme == "http") && p.Host != ""
}

func checkURLs(landing string, redirects []string) error {
	if landing != "" && !validURL(landing) {
		return bad("landing URL %q is not an http(s) URL", landing)
	}
	for _, u := range redirects {
		if !validURL(u) {
			return bad("redirect URL %q is not an http(s) URL", u)
		}
	}
	return nil
}

// scopeGroup maps the API's group ("" = all users) to the engine's.
func (s *Server) scopeGroup(g string) (string, error) {
	if g == "" {
		return engine.AllPersons, nil
	}
	if _, err := s.lookupGroup(g); err != nil {
		return "", bad("no group %q", g)
	}
	return g, nil
}

func (s *Server) postOIDC(r *http.Request) (any, error) {
	var req struct {
		Name         string   `json:"name"`
		DisplayName  string   `json:"display_name"`
		LandingURL   string   `json:"landing_url"`
		RedirectURLs []string `json:"redirect_urls"`
		ScopeGroup   string   `json:"scope_group"`
		PKCE         *bool    `json:"pkce"`
		Short        *bool    `json:"short_username"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if !ValidName(req.Name) {
		return nil, bad("application name %q: lower-case letters, digits, - and _, a letter first, at most 32", req.Name)
	}
	if req.LandingURL == "" && len(req.RedirectURLs) > 0 {
		u, _ := url.Parse(req.RedirectURLs[0])
		if u != nil {
			req.LandingURL = u.Scheme + "://" + u.Host + "/"
		}
	}
	if req.LandingURL == "" {
		return nil, bad("give the application's address (landing_url) or its redirect URLs")
	}
	if err := checkURLs(req.LandingURL, req.RedirectURLs); err != nil {
		return nil, err
	}
	g, err := s.scopeGroup(req.ScopeGroup)
	if err != nil {
		return nil, err
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Name
	}
	pkce := req.PKCE == nil || *req.PKCE
	c := engine.OAuth2{Name: req.Name, DisplayName: req.DisplayName, LandingURL: req.LandingURL, RedirectURLs: req.RedirectURLs, PKCE: pkce}
	if err := s.Eng.CreateOAuth2(c); err != nil {
		if errors.Is(err, engine.ErrExists) {
			return nil, conflict("the name %q is taken", req.Name)
		}
		return nil, err
	}
	// a client half made (its scope map or user name setting refused) is taken away again
	undo := func(err error) (any, error) {
		s.Eng.DeleteOAuth2(req.Name)
		return nil, err
	}
	if err := s.Eng.SetScopeMap(req.Name, g, DefaultScopes); err != nil {
		return undo(err)
	}
	// the bare user name unless asked otherwise: GitLab, Redmine and the like take
	// preferred_username as the login name as it is
	if req.Short == nil || *req.Short {
		if err := s.Eng.SetShortName(req.Name, true); err != nil {
			return undo(err)
		}
	}
	sec, err := s.Eng.OAuth2Secret(req.Name, false)
	if err != nil {
		return nil, err
	}
	got, err := s.lookupOIDC(req.Name)
	if err != nil {
		return nil, err
	}
	o := s.oidcOut(got)
	o.Secret = sec
	return o, nil
}

func (s *Server) patchOIDC(r *http.Request) (any, error) {
	c, err := s.lookupOIDC(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		DisplayName  *string   `json:"display_name"`
		LandingURL   *string   `json:"landing_url"`
		RedirectURLs *[]string `json:"redirect_urls"`
		ScopeGroup   *string   `json:"scope_group"`
		PKCE         *bool     `json:"pkce"`
		Short        *bool     `json:"short_username"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	land := ""
	if req.LandingURL != nil {
		if land = *req.LandingURL; land == "" {
			return nil, bad("the landing URL cannot be empty")
		}
	}
	var redirects []string
	if req.RedirectURLs != nil {
		redirects = *req.RedirectURLs
		if redirects == nil {
			redirects = []string{}
		}
	}
	if err := checkURLs(land, redirects); err != nil {
		return nil, err
	}
	if req.DisplayName != nil || req.LandingURL != nil || req.RedirectURLs != nil || req.PKCE != nil {
		if err := s.Eng.UpdateOAuth2(c.Name, req.DisplayName, req.LandingURL, redirects, req.PKCE); err != nil {
			return nil, err
		}
	}
	if req.Short != nil {
		if err := s.Eng.SetShortName(c.Name, *req.Short); err != nil {
			return nil, err
		}
	}
	if req.ScopeGroup != nil {
		g, err := s.scopeGroup(*req.ScopeGroup)
		if err != nil {
			return nil, err
		}
		if err := s.Eng.SetScopeMap(c.Name, g, DefaultScopes); err != nil {
			return nil, err
		}
		for old := range c.ScopeMaps {
			if old != g {
				if err := s.Eng.DeleteScopeMap(c.Name, old); err != nil {
					return nil, err
				}
			}
		}
	}
	if c, err = s.lookupOIDC(c.Name); err != nil {
		return nil, err
	}
	return s.oidcOut(c), nil
}

func (s *Server) postOIDCSecret(r *http.Request) (any, error) {
	c, err := s.lookupOIDC(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Reset bool `json:"reset"`
	}
	if err := decodeOpt(r, &req); err != nil {
		return nil, err
	}
	sec, err := s.Eng.OAuth2Secret(c.Name, req.Reset)
	if err != nil {
		return nil, err
	}
	return map[string]any{"client_id": c.Name, "client_secret": sec}, nil
}

func (s *Server) deleteOIDC(r *http.Request) (any, error) {
	c, err := s.lookupOIDC(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	if err := s.Eng.DeleteOAuth2(c.Name); err != nil {
		return nil, err
	}
	if _, ok := s.State().OIDCRoles[c.Name]; ok {
		if err := s.update(func(st *State) error { delete(st.OIDCRoles, c.Name); return nil }, false); err != nil {
			return nil, err
		}
	}
	return map[string]any{}, nil
}

// putOIDCRoles: an application says what its groups mean there (keelOS sends its mapping:
// keel-admins = admin, keel-operators = operate…); the page shows it with the groups that are
// missing. {"roles": {group: text}, "by": "keelOS"}; empty roles forget it.
func (s *Server) putOIDCRoles(r *http.Request) (any, error) {
	c, err := s.lookupOIDC(r.PathValue("name"))
	if err != nil {
		return nil, err
	}
	var req struct {
		Roles map[string]string `json:"roles"`
		By    string            `json:"by"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	if len(req.Roles) > 64 || len(req.By) > 64 {
		return nil, bad("too many roles or too long a name")
	}
	for g, v := range req.Roles {
		if !ValidName(g) || len(v) > 64 {
			return nil, bad("role %q: a group name and a short text", g)
		}
	}
	err = s.update(func(st *State) error {
		if len(req.Roles) == 0 {
			delete(st.OIDCRoles, c.Name)
			return nil
		}
		if st.OIDCRoles == nil {
			st.OIDCRoles = map[string]OIDCRoles{}
		}
		st.OIDCRoles[c.Name] = OIDCRoles{By: req.By, Roles: req.Roles}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	return s.oidcOut(c), nil
}
