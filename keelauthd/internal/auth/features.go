package auth

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// features.go: feature modules, attributes on an account (docs/02 §10). Authentication is the
// base; a feature module adds a group of attributes to every account together with everything
// that handles them: the admin's place to set them, the field in the user and sync APIs, MCP,
// backups (they live in state.json). A module is one declaration below; the page, the API and
// the checks come out of it, and only what a declaration cannot say is code (Check). Switched on
// and off like the other modules (modules.go, kind "feature"), off by default; off hides it
// everywhere but keeps the values until DELETE /v1/features/{name}/data.

// Text is one text in the page's languages.
type Text map[string]string

// FieldDef is one attribute of a feature module.
type FieldDef struct {
	Name     string `json:"name"`
	Title    Text   `json:"title"`
	Type     string `json:"type"` // text | host | port | int | bool
	Required bool   `json:"required,omitempty"`
	Max      int    `json:"max,omitempty"`     // text: characters; int: the largest value
	Pattern  string `json:"pattern,omitempty"` // text: the whole value must match
	Default  any    `json:"default,omitempty"` // kept when the field is left empty
	Unique   bool   `json:"unique,omitempty"`  // rows: no two rows alike (case ignored)
	re       *regexp.Regexp
}

// FeatureDef declares a feature module.
type FeatureDef struct {
	Name     string     `json:"name"`
	Title    Text       `json:"title"`
	Help     Text       `json:"help"`
	Rows     bool       `json:"rows"` // a list of rows (maybe none) rather than one set of fields
	Fields   []FieldDef `json:"fields"`
	SelfEdit bool       `json:"self_edit"` // the person may change it through a front end (§9.5)
	// Check: what the fields cannot say (rows already checked one by one); nil = nothing.
	Check func(s *Server, user string, rows []map[string]any) error `json:"-"`
}

var featureDefs = []*FeatureDef{
	{
		Name:  "computers",
		Title: Text{"en": "Computers", "zh": "电脑列表", "ja": "コンピューター一覧"},
		Help: Text{"en": "The office computers this person may reach from home (through the gateway).",
			"zh": "这个人在家能连的公司电脑（经网关）。", "ja": "この人が自宅から（ゲートウェイ経由で）接続できる社内のコンピューター。"},
		Rows: true,
		Fields: []FieldDef{
			{Name: "name", Title: Text{"en": "Name", "zh": "名字", "ja": "名前"}, Type: "text", Required: true, Max: 32,
				Pattern: `[A-Za-z0-9._-]+`, Unique: true},
			{Name: "address", Title: Text{"en": "Address", "zh": "地址", "ja": "アドレス"}, Type: "host", Required: true},
			{Name: "port", Title: Text{"en": "Port", "zh": "端口", "ja": "ポート"}, Type: "port", Default: 3389},
		},
	},
}

func init() {
	for _, f := range featureDefs {
		for i := range f.Fields {
			if p := f.Fields[i].Pattern; p != "" {
				f.Fields[i].re = regexp.MustCompile(`^(?:` + p + `)$`)
			}
		}
		moduleDefs = append(moduleDefs, moduleDef{Name: f.Name, Feature: true})
	}
}

func findFeature(name string) *FeatureDef {
	for _, f := range featureDefs {
		if f.Name == name {
			return f
		}
	}
	return nil
}

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validHost(h string) bool {
	if ip := net.ParseIP(h); ip != nil {
		return ip.To4() != nil
	}
	if len(h) == 0 || len(h) > 253 || strings.Trim(h, "0123456789.") == "" { // all digits and dots: a bad IPv4
		return false
	}
	for _, l := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	return true
}

// value checks one field's value (nil or "" = not given) and gives what is kept.
func (fd *FieldDef) value(v any) (any, bool, error) {
	if s, ok := v.(string); ok {
		v = strings.TrimSpace(s)
		if v == "" {
			v = nil
		}
	}
	if v == nil {
		if fd.Default != nil {
			return fd.Default, true, nil
		}
		if fd.Required {
			return nil, false, fmt.Errorf("%s: required", fd.Name)
		}
		return nil, false, nil
	}
	num := func() (int, error) {
		switch x := v.(type) {
		case float64:
			if x != math.Trunc(x) {
				return 0, fmt.Errorf("%s: not a whole number", fd.Name)
			}
			return int(x), nil
		case string:
			n, err := strconv.Atoi(x)
			if err != nil {
				return 0, fmt.Errorf("%s: not a number", fd.Name)
			}
			return n, nil
		}
		return 0, fmt.Errorf("%s: not a number", fd.Name)
	}
	switch fd.Type {
	case "text", "host":
		s, ok := v.(string)
		if !ok {
			return nil, false, fmt.Errorf("%s: not text", fd.Name)
		}
		if fd.Type == "host" {
			if !validHost(s) {
				return nil, false, fmt.Errorf("%s: not an IPv4 address or host name", fd.Name)
			}
			return s, true, nil
		}
		if fd.Max > 0 && len([]rune(s)) > fd.Max {
			return nil, false, fmt.Errorf("%s: at most %d characters", fd.Name, fd.Max)
		}
		if fd.re != nil && !fd.re.MatchString(s) {
			return nil, false, fmt.Errorf("%s: only %s", fd.Name, describePattern(fd.Pattern))
		}
		return s, true, nil
	case "port":
		n, err := num()
		if err != nil {
			return nil, false, err
		}
		if n < 1 || n > 65535 {
			return nil, false, fmt.Errorf("%s: 1 to 65535", fd.Name)
		}
		return n, true, nil
	case "int":
		n, err := num()
		if err != nil {
			return nil, false, err
		}
		if fd.Max > 0 && n > fd.Max {
			return nil, false, fmt.Errorf("%s: at most %d", fd.Name, fd.Max)
		}
		return n, true, nil
	case "bool":
		b, ok := v.(bool)
		if !ok {
			return nil, false, fmt.Errorf("%s: true or false", fd.Name)
		}
		return b, true, nil
	}
	return nil, false, fmt.Errorf("%s: unknown type %q", fd.Name, fd.Type)
}

func describePattern(p string) string {
	if p == `[A-Za-z0-9._-]+` {
		return "letters, digits, '.', '_' and '-'"
	}
	return "characters matching " + p
}

// row checks one row: no unknown keys, every field by its rule.
func (f *FeatureDef) row(in map[string]any) (map[string]any, error) {
	for k := range in {
		if !slices.ContainsFunc(f.Fields, func(fd FieldDef) bool { return fd.Name == k }) {
			return nil, fmt.Errorf("%s: no such field", k)
		}
	}
	out := map[string]any{}
	for i := range f.Fields {
		fd := &f.Fields[i]
		v, keep, err := fd.value(in[fd.Name])
		if err != nil {
			return nil, err
		}
		if keep {
			out[fd.Name] = v
		}
	}
	return out, nil
}

// normalize checks a whole value (JSON) for user; nil = cleared.
func (s *Server) normalizeFeature(f *FeatureDef, user string, raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var rows []map[string]any
	if f.Rows {
		if err := json.Unmarshal(raw, &rows); err != nil {
			return nil, fmt.Errorf("%s: a list of rows", f.Name)
		}
	} else {
		var one map[string]any
		if err := json.Unmarshal(raw, &one); err != nil {
			return nil, fmt.Errorf("%s: an object", f.Name)
		}
		rows = []map[string]any{one}
	}
	seen := map[string]map[string]bool{}
	for i := range rows {
		r, err := f.row(rows[i])
		where := f.Name
		if f.Rows {
			where = fmt.Sprintf("%s row %d", f.Name, i+1)
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
		}
		for _, fd := range f.Fields {
			if fd.Unique && f.Rows {
				k := strings.ToLower(fmt.Sprint(r[fd.Name]))
				if seen[fd.Name] == nil {
					seen[fd.Name] = map[string]bool{}
				}
				if seen[fd.Name][k] {
					return nil, fmt.Errorf("%s: %s: %v is already in the list", where, fd.Name, r[fd.Name])
				}
				seen[fd.Name][k] = true
			}
		}
		rows[i] = r
	}
	if f.Check != nil {
		if err := f.Check(s, user, rows); err != nil {
			return nil, fmt.Errorf("%s: %v", f.Name, err)
		}
	}
	if f.Rows {
		if len(rows) == 0 {
			return nil, nil
		}
		return json.Marshal(rows)
	}
	return json.Marshal(rows[0])
}

// enabledFeatures: the feature modules that are on.
func (s *Server) enabledFeatures() []string {
	out := []string{}
	for _, f := range featureDefs {
		if s.moduleOn(f.Name) {
			out = append(out, f.Name)
		}
	}
	return out
}

// featureValues: the user's values of those of names that are on ([] or {} when none).
func (s *Server) featureValues(user string, names []string) map[string]any {
	out := map[string]any{}
	d := s.State().Users[user]
	for _, n := range names {
		f := findFeature(n)
		if f == nil || !s.moduleOn(n) {
			continue
		}
		var v any
		if d != nil && len(d.Features[n]) > 0 {
			json.Unmarshal(d.Features[n], &v)
		}
		if v == nil {
			if f.Rows {
				v = []any{}
			} else {
				v = map[string]any{}
			}
		}
		out[n] = v
	}
	return out
}

// setFeatures replaces the given modules' values of user, all checked before any is kept;
// only modules in allowed (nil = any) that are on.
func (s *Server) setFeatures(user string, in map[string]json.RawMessage, allowed []string) error {
	keep := map[string]json.RawMessage{}
	for n, raw := range in {
		f := findFeature(n)
		if f == nil {
			return bad("no feature module %q", n)
		}
		if !s.moduleOn(n) {
			return bad("the feature module %s is off (Settings → Modules)", n)
		}
		if allowed != nil && !slices.Contains(allowed, n) {
			return coded(http.StatusForbidden, "not_self_edit", "%s cannot be changed here", n)
		}
		v, err := s.normalizeFeature(f, user, raw)
		if err != nil {
			return bad("%v", err)
		}
		keep[n] = v
	}
	if len(keep) == 0 {
		return nil
	}
	return s.update(func(st *State) error {
		d := st.user(user)
		for n, v := range keep {
			if v == nil {
				delete(d.Features, n)
				continue
			}
			if d.Features == nil {
				d.Features = map[string]json.RawMessage{}
			}
			d.Features[n] = v
		}
		return nil
	}, true)
}

func (s *Server) usersWithFeature(name string) int {
	n := 0
	for _, d := range s.State().Users {
		if len(d.Features[name]) > 0 {
			n++
		}
	}
	return n
}

// getFeatures: GET /v1/features, the declarations for the page.
func (s *Server) getFeatures(r *http.Request) (any, error) {
	out := []map[string]any{}
	for _, f := range featureDefs {
		out = append(out, map[string]any{"name": f.Name, "title": f.Title, "help": f.Help, "rows": f.Rows, "fields": f.Fields,
			"self_edit": f.SelfEdit, "enabled": s.moduleOn(f.Name), "users_with_data": s.usersWithFeature(f.Name)})
	}
	return map[string]any{"features": out}, nil
}

// deleteFeatureData: DELETE /v1/features/{name}/data, the module's values off every account
// (only while it is off).
func (s *Server) deleteFeatureData(r *http.Request) (any, error) {
	name := r.PathValue("name")
	if findFeature(name) == nil {
		return nil, notFound("no feature module %q", name)
	}
	if s.moduleOn(name) {
		return nil, conflict("switch %s off first", name)
	}
	n := 0
	err := s.update(func(st *State) error {
		for _, d := range st.Users {
			if len(d.Features[name]) > 0 {
				delete(d.Features, name)
				n++
			}
		}
		return nil
	}, true)
	if err != nil {
		return nil, err
	}
	s.Log.Printf("features: %s removed from %d accounts", name, n)
	return map[string]any{"removed": n}, nil
}

// features a sync key may read (only known ones are kept).
func checkKeyFeatures(names []string) ([]string, error) {
	out := []string{}
	for _, n := range names {
		if findFeature(n) == nil {
			return nil, bad("no feature module %q", n)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// postSelfFeatures: the person changes their own values of the self_edit modules their key reads.
func (s *Server) postSelfFeatures(r *http.Request) (any, error) {
	req, _, key, err := s.selfProve(r)
	if err != nil {
		return nil, err
	}
	allowed := []string{}
	for _, n := range key.Features {
		if f := findFeature(n); f != nil && f.SelfEdit {
			allowed = append(allowed, n)
		}
	}
	if err := s.setFeatures(req.Name, req.Features, allowed); err != nil {
		return nil, err
	}
	return s.selfStatus(req.Name, key)
}
