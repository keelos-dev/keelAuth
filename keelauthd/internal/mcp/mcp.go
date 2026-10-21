// Package mcp is keelauthd's MCP server (Model Context Protocol, JSON-RPC 2.0): the API as tools
// an AI can call, answered at POST /mcp (streamable HTTP, JSON answers only). The protocol part
// is keelOS's keel/internal/mcp (same versions, same messages); the tools are keelAuth's
// (tools.go), each a call of the API in this process as the caller.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Doer is the API: the in-process handler for /mcp.
type Doer interface {
	Do(method, path string, body, out any) error
}

// Versions are the protocol versions keel speaks, newest first.
var Versions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// Server answers MCP messages with API calls.
type Server struct {
	API     Doer
	Version string // keelauthd's
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// JSON-RPC error codes.
const (
	errParse          = -32700
	errInvalidRequest = -32600
	errNoMethod       = -32601
	errParams         = -32602
)

// Handle answers one message (or a batch). It returns nil for notifications.
func (s *Server) Handle(msg []byte) []byte {
	msg = []byte(strings.TrimSpace(string(msg)))
	if len(msg) > 0 && msg[0] == '[' {
		var batch []json.RawMessage
		if err := json.Unmarshal(msg, &batch); err != nil || len(batch) == 0 {
			return marshal(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{errParse, "parse error"}})
		}
		var out []json.RawMessage
		for _, m := range batch {
			if r := s.one(m); r != nil {
				out = append(out, marshal(*r))
			}
		}
		if len(out) == 0 {
			return nil
		}
		b, _ := json.Marshal(out)
		return b
	}
	if r := s.one(msg); r != nil {
		return marshal(*r)
	}
	return nil
}

func marshal(r response) []byte {
	b, _ := json.Marshal(r)
	return b
}

func (s *Server) one(msg []byte) *response {
	var req request
	if err := json.Unmarshal(msg, &req); err != nil {
		return &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{errParse, "parse error: " + err.Error()}}
	}
	if req.Method == "" {
		if req.ID != nil { // a response to us: we send no requests, ignore
			return nil
		}
		return &response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{errInvalidRequest, "no method"}}
	}
	notification := req.ID == nil
	res, rerr := s.call(req.Method, req.Params)
	if notification {
		return nil
	}
	r := &response{JSONRPC: "2.0", ID: req.ID}
	if rerr != nil {
		r.Error = rerr
	} else {
		r.Result = res
	}
	return r
}

func (s *Server) call(method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(params, &p)
		v := Versions[0]
		for _, x := range Versions {
			if x == p.ProtocolVersion {
				v = x
			}
		}
		return map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "keelauth", "title": "keelAuth (office accounts: LDAP, SSO, RADIUS)", "version": s.Version},
			"instructions": "keelAuth keeps an office's user accounts and groups and serves them over LDAP, SSO (OIDC) and RADIUS. " +
				"Users and groups are named by their short lower-case name. Passwords keelAuth makes are shown once: pass them on to the person. " +
				"A token for this server manages everything; be careful with disabling users and resetting passwords.",
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": toolList()}, nil
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, &rpcError{errParams, "params: " + err.Error()}
		}
		t, ok := toolByName[p.Name]
		if !ok {
			return nil, &rpcError{errParams, "unknown tool " + p.Name}
		}
		args := map[string]any{}
		if len(p.Arguments) > 0 && string(p.Arguments) != "null" {
			if err := json.Unmarshal(p.Arguments, &args); err != nil {
				return nil, &rpcError{errParams, "arguments: " + err.Error()}
			}
		}
		out, err := t.Run(s.API, args)
		if err != nil {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": "error: " + err.Error()}}, "isError": true}, nil
		}
		var text string
		if str, ok := out.(string); ok {
			text = str
		} else {
			b, _ := json.MarshalIndent(out, "", "  ")
			text = string(b)
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}, "isError": false}, nil
	}
	if strings.HasPrefix(method, "notifications/") {
		return nil, nil
	}
	return nil, &rpcError{errNoMethod, "method not found: " + method}
}

// ServeStdio reads messages a line each from r and writes the answers a line each to w, until
// r ends or ctx is done.
func (s *Server) ServeStdio(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	var mu sync.Mutex
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil
		}
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if out := s.Handle(line); out != nil {
			mu.Lock()
			_, err := w.Write(append(out, '\n'))
			mu.Unlock()
			if err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// HTTP returns the handler of POST /mcp: api(r) is the API as the caller of r.
func HTTP(version string, api func(r *http.Request) Doer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, `{"error":"Content-Type: application/json"}`, http.StatusUnsupportedMediaType)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, `{"error":"body"}`, http.StatusBadRequest)
			return
		}
		s := &Server{API: api(r), Version: version}
		out := s.Handle(b)
		if out == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
}

// Tool is one MCP tool: its description, input schema and what it calls.
type Tool struct {
	Name        string                                           `json:"name"`
	Title       string                                           `json:"title,omitempty"`
	Description string                                           `json:"description"`
	InputSchema map[string]any                                   `json:"inputSchema"`
	Annotations map[string]any                                   `json:"annotations,omitempty"`
	Run         func(api Doer, args map[string]any) (any, error) `json:"-"`
}

var toolByName = func() map[string]Tool {
	m := map[string]Tool{}
	for _, t := range tools {
		m[t.Name] = t
	}
	return m
}()

func toolList() []Tool { return tools }

// Tools are the tools (for tests and docs).
func Tools() []Tool { return tools }
