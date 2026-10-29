package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The page's branding (docs/02 section 3.9): a company shows its own name ("Log in to Acme")
// and logo instead of keelAuth's. The name has a text per language; a language left empty shows
// the first one that is set, in the order of BrandLangs. The logo is one image file, kept in
// state.json (so backups and the hand-over to a new system disk carry it) and served to
// everybody at GET /brand/logo.

// BrandLangs are the page's languages, in the order the fallback looks.
var BrandLangs = []string{"zh", "en", "ja"}

const (
	brandNameMax = 60        // runes per name
	brandLogoMax = 256 << 10 // bytes
)

// brandTypes are the logo types taken, and how each is recognised.
var brandTypes = map[string]func([]byte) bool{
	"image/png":     func(b []byte) bool { return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")) },
	"image/jpeg":    func(b []byte) bool { return bytes.HasPrefix(b, []byte("\xff\xd8\xff")) },
	"image/webp":    func(b []byte) bool { return len(b) > 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP" },
	"image/svg+xml": isSVG,
}

// isSVG: an SVG document without scripts or event handlers (it is shown in <img>, where they
// would not run anyway; refused so that a copy of the file elsewhere is safe too).
func isSVG(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	l := strings.ToLower(string(b))
	i := strings.Index(l, "<svg")
	if i < 0 {
		return false
	}
	head := strings.TrimSpace(l[:i])
	if head != "" && !strings.HasPrefix(head, "<?xml") && !strings.HasPrefix(head, "<!") {
		return false
	}
	return !strings.Contains(l, "<script") && !strings.Contains(l, "javascript:") && !eventAttr(l)
}

// eventAttr: an on… attribute (onload=, onclick=) anywhere.
func eventAttr(l string) bool {
	for i := 0; ; {
		j := strings.Index(l[i:], " on")
		if j < 0 {
			return false
		}
		k := i + j + 3
		for k < len(l) && (l[k] >= 'a' && l[k] <= 'z') {
			k++
		}
		if k > i+j+3 && k < len(l) && l[k] == '=' {
			return true
		}
		i = i + j + 3
	}
}

// Brand is the setting as kept.
type Brand struct {
	Name     map[string]string `json:"name,omitempty"`
	Logo     []byte            `json:"logo,omitempty"`
	LogoType string            `json:"logo_type,omitempty"`
}

// Tag changes with the logo: the page puts it in the logo's URL so browsers fetch a new one.
func (b Brand) Tag() string {
	if len(b.Logo) == 0 {
		return ""
	}
	h := sha256.Sum256(b.Logo)
	return hex.EncodeToString(h[:6])
}

// NameFor is the name in lang, or the first one set, or "" (the page shows keelAuth).
func (b Brand) NameFor(lang string) string {
	if n := b.Name[lang]; n != "" {
		return n
	}
	for _, l := range BrandLangs {
		if n := b.Name[l]; n != "" {
			return n
		}
	}
	return ""
}

func (b Brand) out() map[string]any {
	name := map[string]string{}
	for _, l := range BrandLangs {
		if n := b.Name[l]; n != "" {
			name[l] = n
		}
	}
	return map[string]any{"name": name, "logo": len(b.Logo) > 0, "logo_type": b.LogoType, "logo_tag": b.Tag(), "logo_size": len(b.Logo)}
}

// GET /brand (no login: the login page shows it), GET /v1/brand
func (s *Server) getBrand(r *http.Request) (any, error) { return s.State().Brand.out(), nil }

// PUT /v1/brand {"name": {"zh": "…", "en": "…", "ja": "…"}}: the names (a missing language
// is cleared); the logo has its own calls.
func (s *Server) putBrand(r *http.Request) (any, error) {
	var req struct {
		Name map[string]string `json:"name"`
	}
	if err := decode(r, &req); err != nil {
		return nil, err
	}
	name := map[string]string{}
	for l, n := range req.Name {
		if !brandLang(l) {
			return nil, bad("name.%s: not one of %s", l, strings.Join(BrandLangs, ", "))
		}
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if utf8.RuneCountInString(n) > brandNameMax {
			return nil, bad("name.%s: at most %d characters", l, brandNameMax)
		}
		for _, c := range n {
			if unicode.IsControl(c) {
				return nil, bad("name.%s: no control characters", l)
			}
		}
		name[l] = n
	}
	if len(name) == 0 {
		name = nil
	}
	if err := s.update(func(st *State) error { st.Brand.Name = name; return nil }, false); err != nil {
		return nil, err
	}
	return s.State().Brand.out(), nil
}

func brandLang(l string) bool {
	for _, x := range BrandLangs {
		if x == l {
			return true
		}
	}
	return false
}

// PUT /v1/brand/logo: the body is the image, Content-Type its type (PNG, JPEG, WebP or SVG).
func (s *Server) putBrandLogo(r *http.Request) (any, error) {
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	ct = strings.TrimSpace(strings.ToLower(ct))
	is, ok := brandTypes[ct]
	if !ok {
		return nil, bad("Content-Type %q: the logo is a PNG, JPEG, WebP or SVG file", ct)
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, brandLogoMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > brandLogoMax {
		return nil, bad("the logo is larger than %d KB", brandLogoMax>>10)
	}
	if len(b) == 0 || !is(b) {
		return nil, bad("this is not a %s file (an SVG may not contain scripts)", ct)
	}
	if err := s.update(func(st *State) error { st.Brand.Logo, st.Brand.LogoType = b, ct; return nil }, false); err != nil {
		return nil, err
	}
	return s.State().Brand.out(), nil
}

// DELETE /v1/brand/logo
func (s *Server) deleteBrandLogo(r *http.Request) (any, error) {
	if err := s.update(func(st *State) error { st.Brand.Logo, st.Brand.LogoType = nil, ""; return nil }, false); err != nil {
		return nil, err
	}
	return s.State().Brand.out(), nil
}

// GET /brand/logo (no login): the logo file. The page asks with ?v=<tag>, so it may be cached
// until the tag changes.
func (s *Server) getBrandLogo(w http.ResponseWriter, r *http.Request) {
	b := s.State().Brand
	if len(b.Logo) == 0 {
		http.Error(w, "no logo", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", b.LogoType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	w.Header().Set("ETag", `"`+b.Tag()+`"`)
	if r.Header.Get("If-None-Match") == `"`+b.Tag()+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(b.Logo)
}
