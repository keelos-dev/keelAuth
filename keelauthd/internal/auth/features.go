package auth

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"net"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"keelauth/internal/module/ldap"
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
	Type     string `json:"type"` // text | host | port | int | bool | choice
	Required bool   `json:"required,omitempty"`
	Max      int    `json:"max,omitempty"`     // text: characters; int: the largest value
	Pattern  string `json:"pattern,omitempty"` // text: the whole value must match
	Default  any    `json:"default,omitempty"` // kept when the field is left empty
	Unique   bool   `json:"unique,omitempty"`  // rows: no two rows alike (case ignored)
	// UniqueAll: no two accounts have the same value (one-row modules; an empty value is nobody's).
	UniqueAll bool `json:"unique_all,omitempty"`
	// AdminLen: the admin may fix the value's exact length (FeatureConf.Len; 0 = any up to Max).
	AdminLen bool `json:"admin_len,omitempty"`
	// LDAP: the attribute the LDAP module gives the value out as; "" = not in LDAP.
	LDAP string `json:"ldap,omitempty"`
	// List: a column of the user list (and, for a choice, a filter there).
	List bool `json:"list,omitempty"`
	re   *regexp.Regexp
}

// LDAPJoin is an LDAP attribute put together from several fields, a space between them.
type LDAPJoin struct {
	Attr   string   `json:"attr"`
	Fields []string `json:"fields"`
}

// FeatureOption is one option of a choice field: a code that never changes (what the APIs, the
// sync and LDAP give) and what the page calls it.
type FeatureOption struct {
	Code  string `json:"code"`
	Title Text   `json:"title"`
}

// FeatureConf is the admin's settings of a feature module (PUT /v1/features/{name}/conf): the
// options of its choice fields and the fixed lengths of its admin_len fields, by field name.
type FeatureConf struct {
	Options map[string][]FeatureOption `json:"options,omitempty"`
	Len     map[string]int             `json:"len,omitempty"`
}

func (c *FeatureConf) clone() *FeatureConf {
	o := &FeatureConf{Len: maps.Clone(c.Len)}
	if c.Options != nil {
		o.Options = map[string][]FeatureOption{}
		for k, v := range c.Options {
			o.Options[k] = slices.Clone(v)
		}
	}
	return o
}

// FeatureDef declares a feature module.
type FeatureDef struct {
	Name     string     `json:"name"`
	Title    Text       `json:"title"`
	Help     Text       `json:"help"`
	Rows     bool       `json:"rows"` // a list of rows (maybe none) rather than one set of fields
	Fields   []FieldDef `json:"fields"`
	SelfEdit bool       `json:"self_edit"` // the person may change it through a front end (§9.5)
	// LDAPClass: the objectClass people get in LDAP for a bind that reads the module; LDAPJoin:
	// attributes made of several fields.
	LDAPClass string     `json:"ldap_class,omitempty"`
	LDAPJoin  []LDAPJoin `json:"ldap_join,omitempty"`
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
	// employee and names (docs/02 §10.4): the fields are inetOrgPerson's (RFC 2798) and, for the
	// readings, Active Directory's msDS-Phonetic* (what Japanese address books sort by).
	{
		Name:  "employee",
		Title: Text{"en": "Employee", "zh": "员工信息", "ja": "社員情報"},
		Help: Text{"en": "The employee number (only a number: given once, its digits mean nothing) and the employment type (a field of its own, which may change). An account without a number is not an employee.",
			"zh": "员工号码（只是一个号码：发了不变，数字不表示意思）和雇佣形态（单独的字段，可以改）。没有号码的账号不是员工。",
			"ja": "社員番号（ただの番号：一度決めたら変えず、数字に意味を持たせない）と雇用形態（独立した項目で、変更できる）。番号のないアカウントは社員ではありません。"},
		LDAPClass: "inetOrgPerson",
		Fields: []FieldDef{
			{Name: "employeeNumber", Title: Text{"en": "Employee number", "zh": "员工号码", "ja": "社員番号"}, Type: "text", Max: 32,
				Pattern: `[0-9]+`, UniqueAll: true, AdminLen: true, LDAP: "employeeNumber", List: true},
			{Name: "employeeType", Title: Text{"en": "Employment type", "zh": "雇佣形态", "ja": "雇用形態"}, Type: "choice",
				LDAP: "employeeType", List: true},
		},
	},
	{
		Name:  "names",
		Title: Text{"en": "Names", "zh": "姓名", "ja": "氏名"},
		Help: Text{"en": "Family and given name, and how they are read (e.g. in katakana). The display name stays what the administrator typed; it is not put together from these.",
			"zh": "姓、名和它们的读音（如片假名）。显示名照旧由管理员填，不从这里拼。",
			"ja": "姓・名とその読み（カタカナなど）。表示名は管理者が入力したままで、ここからは組み立てません。"},
		LDAPClass: "inetOrgPerson",
		LDAPJoin:  []LDAPJoin{{Attr: "msDS-PhoneticDisplayName", Fields: []string{"phoneticLastName", "phoneticFirstName"}}},
		Fields: []FieldDef{
			{Name: "sn", Title: Text{"en": "Family name", "zh": "姓", "ja": "姓"}, Type: "text", Max: 64, LDAP: "sn"},
			{Name: "givenName", Title: Text{"en": "Given name", "zh": "名", "ja": "名"}, Type: "text", Max: 64, LDAP: "givenName"},
			{Name: "phoneticLastName", Title: Text{"en": "Family name (reading)", "zh": "姓的读音", "ja": "姓（読み）"}, Type: "text", Max: 64,
				LDAP: "msDS-PhoneticLastName"},
			{Name: "phoneticFirstName", Title: Text{"en": "Given name (reading)", "zh": "名的读音", "ja": "名（読み）"}, Type: "text", Max: 64,
				LDAP: "msDS-PhoneticFirstName"},
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
	case "text", "host", "choice": // a choice's code is checked against the admin's options (checkConf)
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
	switch p {
	case `[A-Za-z0-9._-]+`:
		return "letters, digits, '.', '_' and '-'"
	case `[0-9]+`:
		return "digits"
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
		if err := f.checkConf(s.State(), r); err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
		}
		if err := f.clash(s.State(), user, r); err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
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
	if len(rows[0]) == 0 { // every field left empty: nothing kept
		return nil, nil
	}
	return json.Marshal(rows[0])
}

// conf: the admin's settings of a module (never nil).
func (st *State) featureConf(name string) *FeatureConf {
	if c := st.FeatureConf[name]; c != nil {
		return c
	}
	return &FeatureConf{}
}

// checkConf: what the admin's settings say about a row: a choice is one of the options, an
// admin_len field has the fixed length.
func (f *FeatureDef) checkConf(st *State, r map[string]any) error {
	c := st.featureConf(f.Name)
	for i := range f.Fields {
		fd := &f.Fields[i]
		v, ok := r[fd.Name].(string)
		if !ok {
			continue
		}
		if fd.Type == "choice" {
			codes := []string{}
			for _, o := range c.Options[fd.Name] {
				codes = append(codes, o.Code)
			}
			switch {
			case len(codes) == 0:
				return fmt.Errorf("%s: no options yet (Settings → Modules → %s)", fd.Name, f.Name)
			case !slices.Contains(codes, v):
				return fmt.Errorf("%s: %q is not one of %s", fd.Name, v, strings.Join(codes, ", "))
			}
		}
		if n := c.Len[fd.Name]; fd.AdminLen && n > 0 && len([]rune(v)) != n {
			return fmt.Errorf("%s: exactly %d characters", fd.Name, n)
		}
	}
	return nil
}

// one is the module's value of an account as an object (one-row modules); nil = none.
func (d *UserData) one(module string) map[string]any {
	if d == nil || len(d.Features[module]) == 0 {
		return nil
	}
	var v map[string]any
	json.Unmarshal(d.Features[module], &v)
	return v
}

// clash: a unique_all field's value that another account has.
func (f *FeatureDef) clash(st *State, user string, r map[string]any) error {
	if f.Rows {
		return nil
	}
	for i := range f.Fields {
		fd := &f.Fields[i]
		v, ok := r[fd.Name]
		if !fd.UniqueAll || !ok {
			continue
		}
		for n, d := range st.Users {
			if o := d.one(f.Name); n != user && o != nil && o[fd.Name] != nil && fmt.Sprint(o[fd.Name]) == fmt.Sprint(v) {
				return fmt.Errorf("%s: %v is already %s's", fd.Name, v, n)
			}
		}
	}
	return nil
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
			if f := findFeature(n); !f.Rows { // again under the lock: two requests at once
				var r map[string]any
				json.Unmarshal(v, &r)
				if err := f.clash(st, user, r); err != nil {
					return bad("%s: %v", n, err)
				}
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
		m := map[string]any{"name": f.Name, "title": f.Title, "help": f.Help, "rows": f.Rows, "fields": f.Fields,
			"self_edit": f.SelfEdit, "enabled": s.moduleOn(f.Name), "users_with_data": s.usersWithFeature(f.Name)}
		if f.LDAPClass != "" {
			m["ldap_class"] = f.LDAPClass
		}
		if len(f.LDAPJoin) > 0 {
			m["ldap_join"] = f.LDAPJoin
		}
		if f.configurable() {
			m["conf"] = s.featureConfOut(f)
		}
		out = append(out, m)
	}
	return map[string]any{"features": out}, nil
}

// configurable: the module has settings of the admin's (options, a length).
func (f *FeatureDef) configurable() bool {
	return slices.ContainsFunc(f.Fields, func(fd FieldDef) bool { return fd.Type == "choice" || fd.AdminLen })
}

// featureConfOut: the settings with every configurable field present.
func (s *Server) featureConfOut(f *FeatureDef) map[string]any {
	c := s.State().featureConf(f.Name)
	opts, lens := map[string][]FeatureOption{}, map[string]int{}
	for _, fd := range f.Fields {
		if fd.Type == "choice" {
			opts[fd.Name] = append([]FeatureOption{}, c.Options[fd.Name]...)
		}
		if fd.AdminLen {
			lens[fd.Name] = c.Len[fd.Name]
		}
	}
	return map[string]any{"options": opts, "len": lens}
}

var optionCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// putFeatureConf: PUT /v1/features/{name}/conf {"options": {field: [{code, title}]}, "len":
// {field: n}}: each field given is replaced, the others stay. An option that accounts still
// have cannot go, and a length the kept values do not have cannot be set: both say who.
func (s *Server) putFeatureConf(r *http.Request) (any, error) {
	f := findFeature(r.PathValue("name"))
	if f == nil {
		return nil, notFound("no feature module %q", r.PathValue("name"))
	}
	var req FeatureConf
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	field := func(name string) *FieldDef {
		for i := range f.Fields {
			if f.Fields[i].Name == name {
				return &f.Fields[i]
			}
		}
		return nil
	}
	for name, opts := range req.Options {
		if fd := field(name); fd == nil || fd.Type != "choice" {
			return nil, bad("%s: %s is not a choice field", f.Name, name)
		}
		seen := map[string]bool{}
		for i := range opts {
			o := &opts[i]
			o.Code = strings.TrimSpace(o.Code)
			switch {
			case !optionCodeRE.MatchString(o.Code):
				return nil, bad("%s option %d: the code %q: lower-case letters, digits, - and _, a letter first, at most 32", name, i+1, o.Code)
			case seen[o.Code]:
				return nil, bad("%s option %d: the code %s is there twice", name, i+1, o.Code)
			}
			seen[o.Code] = true
			title := Text{}
			for lang, x := range o.Title {
				x = strings.TrimSpace(x)
				switch {
				case lang != "en" && lang != "zh" && lang != "ja":
					return nil, bad("%s option %s: titles are en, zh and ja", name, o.Code)
				case len([]rune(x)) > 64:
					return nil, bad("%s option %s: a title of at most 64 characters", name, o.Code)
				case x != "":
					title[lang] = x
				}
			}
			o.Title = title
		}
	}
	for name, n := range req.Len {
		if fd := field(name); fd == nil || !fd.AdminLen {
			return nil, bad("%s: %s has no length to set", f.Name, name)
		} else if n < 0 || (fd.Max > 0 && n > fd.Max) {
			return nil, bad("%s: a length from 1 to %d, or 0 for any", name, fd.Max)
		}
	}
	err := s.update(func(st *State) error {
		c := st.featureConf(f.Name).clone()
		// who has what, to refuse what would leave accounts with values that no longer pass
		users := slices.Sorted(maps.Keys(st.Users))
		holders := func(name string, ok func(v string) bool) []string {
			out := []string{}
			for _, u := range users {
				if v, is := st.Users[u].one(f.Name)[name].(string); is && !ok(v) {
					out = append(out, u)
				}
			}
			return out
		}
		some := func(us []string) string {
			if len(us) > 5 {
				return strings.Join(us[:5], ", ") + ", …"
			}
			return strings.Join(us, ", ")
		}
		for name, opts := range req.Options {
			for _, old := range c.Options[name] {
				if slices.ContainsFunc(opts, func(o FeatureOption) bool { return o.Code == old.Code }) {
					continue
				}
				if us := holders(name, func(v string) bool { return v != old.Code }); len(us) > 0 {
					return conflict("%s: the option %s is still used by %d accounts (%s)", name, old.Code, len(us), some(us))
				}
			}
			if c.Options == nil {
				c.Options = map[string][]FeatureOption{}
			}
			c.Options[name] = opts
		}
		for name, n := range req.Len {
			if n > 0 {
				if us := holders(name, func(v string) bool { return len([]rune(v)) == n }); len(us) > 0 {
					return conflict("%s: %d accounts have a value that is not %d characters long (%s)", name, len(us), n, some(us))
				}
			}
			if c.Len == nil {
				c.Len = map[string]int{}
			}
			c.Len[name] = n
		}
		if st.FeatureConf == nil {
			st.FeatureConf = map[string]*FeatureConf{}
		}
		st.FeatureConf[f.Name] = c
		return nil
	}, true)
	if err != nil {
		return nil, err
	}
	s.Log.Printf("features: %s settings changed", f.Name)
	return map[string]any{"name": f.Name, "conf": s.featureConfOut(f)}, nil
}

// ldapExtras: what the feature modules that are on add to a person's LDAP entry, by module
// (the LDAP module shows each only to a bind that may read it).
func (s *Server) ldapExtras(user string) []ldap.Extra {
	var out []ldap.Extra
	d := s.State().Users[user]
	for _, f := range featureDefs {
		if f.Rows || !s.moduleOn(f.Name) {
			continue
		}
		x := ldap.Extra{Module: f.Name}
		if f.LDAPClass != "" {
			x.Classes = []string{f.LDAPClass}
		}
		v := d.one(f.Name)
		str := func(name string) string {
			if v[name] == nil {
				return ""
			}
			return fmt.Sprint(v[name])
		}
		for _, fd := range f.Fields {
			if val := str(fd.Name); fd.LDAP != "" && val != "" {
				x.Attrs = append(x.Attrs, ldap.Attr{Name: fd.LDAP, Values: []string{val}})
			}
		}
		for _, j := range f.LDAPJoin {
			parts := []string{}
			for _, n := range j.Fields {
				if val := str(n); val != "" {
					parts = append(parts, val)
				}
			}
			if len(parts) > 0 {
				x.Attrs = append(x.Attrs, ldap.Attr{Name: j.Attr, Values: []string{strings.Join(parts, " ")}})
			}
		}
		if len(x.Classes) > 0 || len(x.Attrs) > 0 {
			out = append(out, x)
		}
	}
	return out
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
