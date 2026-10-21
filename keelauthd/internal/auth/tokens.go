package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"keelauth/internal/secret"
)

// MCP tokens (kat_…) and keelNAS sync keys (kas_…): made in the web page's settings, shown
// once, kept as SHA-256. The token's first 8 hex characters after the prefix are its id.

type TokenOut struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Created  string `json:"created"`
	LastUsed string `json:"last_used"`
	Token    string `json:"token,omitempty"`
	Key      string `json:"key,omitempty"`
}

func tokensOut(ts []Token) []TokenOut {
	out := []TokenOut{}
	for _, t := range ts {
		out = append(out, TokenOut{ID: t.ID, Name: t.Name, Created: t.Created, LastUsed: t.LastUsed})
	}
	return out
}

// useToken finds a token (sync: among the sync keys) and notes its use (at most once a
// minute, to keep state.json writes down). It returns the token's id, "" = none.
func (s *Server) useToken(tok string, sync bool) string {
	h := hashToken(tok)
	st := s.State()
	list := st.Tokens
	if sync {
		list = st.SyncKeys
	}
	for _, t := range list {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(h)) != 1 {
			continue
		}
		now := s.now()
		if last, err := time.Parse(time.RFC3339, t.LastUsed); err != nil || now.Sub(last) > time.Minute {
			id := t.ID
			s.update(func(st *State) error {
				l := &st.Tokens
				if sync {
					l = &st.SyncKeys
				}
				for i := range *l {
					if (*l)[i].ID == id {
						(*l)[i].LastUsed = now.Format(time.RFC3339)
					}
				}
				return nil
			}, false)
		}
		return t.ID
	}
	return ""
}

func (s *Server) makeToken(r *http.Request, sync bool) (any, error) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 64 {
		return nil, bad("give the token a name (at most 64 characters): what it is for")
	}
	prefix := tokenPrefix
	if sync {
		prefix = syncKeyPrefix
	}
	raw := secret.Random(24)
	tok := prefix + raw
	t := Token{ID: raw[:8], Name: req.Name, Hash: hashToken(tok), Created: s.now().Format(time.RFC3339)}
	err := s.update(func(st *State) error {
		if sync {
			st.SyncKeys = append(st.SyncKeys, t)
		} else {
			st.Tokens = append(st.Tokens, t)
		}
		return nil
	}, false)
	if err != nil {
		return nil, err
	}
	o := TokenOut{ID: t.ID, Name: t.Name, Created: t.Created}
	if sync {
		o.Key = tok
	} else {
		o.Token = tok
	}
	return o, nil
}

func (s *Server) dropToken(id string, sync bool) (any, error) {
	err := s.update(func(st *State) error {
		l := &st.Tokens
		if sync {
			l = &st.SyncKeys
		}
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
func (s *Server) postToken(r *http.Request) (any, error) { return s.makeToken(r, false) }
func (s *Server) deleteToken(r *http.Request) (any, error) {
	return s.dropToken(r.PathValue("id"), false)
}
func (s *Server) getSyncKeys(r *http.Request) (any, error) {
	return map[string]any{"keys": tokensOut(s.State().SyncKeys)}, nil
}
func (s *Server) postSyncKey(r *http.Request) (any, error) { return s.makeToken(r, true) }
func (s *Server) deleteSyncKey(r *http.Request) (any, error) {
	return s.dropToken(r.PathValue("id"), true)
}
