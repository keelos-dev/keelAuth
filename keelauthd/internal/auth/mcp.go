package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"keelauth/internal/mcp"
)

// inproc is the API called in this process for an MCP tool, as an admin of kind "mcp" (which
// may do what an admin may, but not read the sync accounts).
type inproc struct {
	s *Server
	r *http.Request
	c *Caller
}

func (d inproc) Do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd).WithContext(d.r.Context())
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.RemoteAddr, req.Host = d.r.RemoteAddr, d.r.Host
	req = withCaller(req, &Caller{Name: d.c.Name, Admin: true, Kind: "mcp"})
	rec := httptest.NewRecorder()
	d.s.Handler().ServeHTTP(rec, req)
	b := rec.Body.Bytes()
	if rec.Code >= 300 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return errors.New(e.Error)
		}
		return fmt.Errorf("%d %s: %s", rec.Code, http.StatusText(rec.Code), strings.TrimSpace(string(b)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

func (s *Server) mcpHandler() http.Handler {
	return mcp.HTTP(s.Version, func(r *http.Request) mcp.Doer { return inproc{s: s, r: r, c: caller(r)} })
}
