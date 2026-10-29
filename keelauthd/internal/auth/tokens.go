package auth

import (
	"crypto/subtle"
	"net/http"
	"slices"
	"strings"
	"time"

	"keelauth/internal/secret"
)

// MCP tokens (kat_…), keelNAS sync keys (kas_…) and API keys of other systems (kap_…): made
// in the web page's settings, shown once, kept as SHA-256. The token's first 8 hex
// characters after the prefix are its id.
//
// An API key has a scope: "users" lets another system (a web application that moves its
// accounts to keelAuth, docs/02 §3.11) read users and groups, add users, set passwords and
// group memberships: not delete anybody, not touch settings, SSO, RADIUS, backups or keys.
// "admin" is the whole API except the keys themselves (a leaked key must not mint more).

const (
	kindMCP  = "mcp"
	kindSync = "sync"
	kindAPI  = "api"
)

var tokenPrefixes = map[string]string{kindMCP: tokenPrefix, kindSync: syncKeyPrefix, kindAPI: apiKeyPrefix}

var apiScopes = []string{"users", "admin"}

// usersScope: what an API key with scope "users" may call (the patterns of buildHandler).
var usersScope = map[string]bool{
	"GET /v1/status": true, "GET /v1/users": true, "POST /v1/users": true, "GET /v1/users/{name}": true,
	"PATCH /v1/users/{name}": true, "POST /v1/users/{name}/password": true,
	"GET /v1/groups": true, "POST /v1/groups/{name}/members": true,
}

// keyRoutes: never for an API key, whatever its scope.
var keyRoutes = map[string]bool{
	"GET /v1/tokens": true, "POST /v1/tokens": true, "DELETE /v1/tokens/{id}": true,
	"GET /v1/sync/keys": true, "POST /v1/sync/keys": true, "DELETE /v1/sync/keys/{id}": true,
	"GET /v1/api/keys": true, "POST /v1/api/keys": true, "DELETE /v1/api/keys/{id}": true,
}

type TokenOut struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  string `json:"created"`
	LastUsed string `json:"last_used"`
	Scope    string `json:"scope,omitempty"`
	Token    string `json:"token,omitempty"`
	Key      string `json:"key,omitempty"`
}

func tokensOut(ts []Token) []TokenOut {
	out := []TokenOut{}
	for _, t := range ts {
		out = append(out, TokenOut{ID: t.ID, Name: t.Name, Created: t.Created, LastUsed: t.LastUsed, Scope: t.Scope})
	}
	return out
}

func tokenList(st *State, kind string) *[]Token {
	switch kind {
	case kindSync:
		return &st.SyncKeys
	case kindAPI:
		return &st.APIKeys
	}
	return &st.Tokens
}

// useToken finds a token of the kind and notes its use (at most once a minute, to keep
// state.json writes down). It returns a copy of the token, nil = none.
func (s *Server) useToken(tok, kind string) *Token {
	h := hashToken(tok)
	for _, t := range *tokenList(s.State(), kind) {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) != 1 {
			continue
		}
		now := s.now()
		if last, err := time.Parse(time.RFC3339, t.LastUsed); err != nil || now.Sub(last) > time.Minute {
			id := t.ID
			s.update(func(st *State) error {
				l := tokenList(st, kind)
				for i := range *l {
					if (*l)[i].ID == id {
						(*l)[i].LastUsed = now.Format(time.RFC3339)
					}
				}
				return nil
			}, false)
		}
		t := t
		return &t
	}
	return nil
}

func (s *Server) makeToken(r *http.Request, kind string) (any, error) {
	var req struct {
		Name  string `json:"name"`
		Scope string `json:"scope"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		return nil, bad("give the token a name (at most 64 characters): what it is for")
	}
	if kind == kindAPI {
		if !slices.Contains(apiScopes, req.Scope) {
			return nil, bad("scope must be one of %s", strings.Join(apiScopes, ", "))
		}
	} else {
		req.Scope = ""
	}
	raw := secret.Random(24)
	tok := tokenPrefixes[kind] + raw
	t := Token{ID: raw[:8], Name: req.Name, Hash: hashToken(tok), Created: s.now().Format(time.RFC3339), Scope: req.Scope}
	err := s.update(func(st *State) error {
		l := tokenList(st, kind)
		*l = append(*l, t)
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	o := TokenOut{ID: t.ID, Name: t.Name, Created: t.Created, Scope: t.Scope}
	if kind == kindMCP {
		o.Token = tok
	} else {
		o.Key = tok
	}
	return o, nil
}

func (s *Server) dropToken(id, kind string) (any, error) {
	err := s.update(func(st *State) error {
		l := tokenList(st, kind)
		for i, t := range *l {
			if t.ID == id {
				*l = append((*l)[:i], (*l)[i+1:]...)
				return nil
			}
		}
		return notFound("no token %q", id)
	}, false)
	if err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

func (s *Server) getTokens(r *http.Request) (any, error) {
	return map[string]any{"tokens": tokensOut(s.State().Tokens), "fingerprint": s.Fingerprint()}, nil
}
func (s *Server) postToken(r *http.Request) (any, error) { return s.makeToken(r, kindMCP) }
func (s *Server) deleteToken(r *http.Request) (any, error) {
	return s.dropToken(r.PathValue("id"), kindMCP)
}
func (s *Server) getSyncKeys(r *http.Request) (any, error) {
	return map[string]any{"keys": tokensOut(s.State().SyncKeys)}, nil
}
func (s *Server) postSyncKey(r *http.Request) (any, error) { return s.makeToken(r, kindSync) }
func (s *Server) deleteSyncKey(r *http.Request) (any, error) {
	return s.dropToken(r.PathValue("id"), kindSync)
}
func (s *Server) getAPIKeys(r *http.Request) (any, error) {
	return map[string]any{"keys": tokensOut(s.State().APIKeys), "fingerprint": s.Fingerprint(), "scopes": apiScopes}, nil
}
func (s *Server) postAPIKey(r *http.Request) (any, error) { return s.makeToken(r, kindAPI) }
func (s *Server) deleteAPIKey(r *http.Request) (any, error) {
	return s.dropToken(r.PathValue("id"), kindAPI)
}

// apiAllowed is the check of an API route: admins as before (admin); an API key only within
// its scope. It knows the route's pattern, which admin does not.
func (s *Server) apiAllowed(pat string) func(c *Caller) error {
	return func(c *Caller) error {
		if c.Kind != kindAPI {
			return s.admin(c)
		}
		switch {
		case keyRoutes[pat]:
			return coded(http.StatusForbidden, "scope", "an API key cannot manage keys: do that in the web page")
		case c.Scope == "admin" || usersScope[pat]:
			return nil
		}
		return coded(http.StatusForbidden, "scope", "this key's scope is %q: it cannot call %s", c.Scope, pat)
	}
}
