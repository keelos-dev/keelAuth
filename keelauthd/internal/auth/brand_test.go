package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var tinyPNG = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x0aIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\x0d\x0a\x2d\xb4\x00\x00\x00\x00IEND\xaeB`\x82")

func (r *rig) raw(method, path, ctype string, body []byte, auth string) (int, map[string]any, *httptest.ResponseRecorder) {
	r.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if auth == "" {
		req.Header.Set("Authorization", "Bearer "+r.key)
	}
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	_, out, _ := r.call("GET", "/brand", "none", nil)
	return rec.Code, out, rec
}

func TestBrand(t *testing.T) {
	r := newRig(t)
	// nothing set: no names, no logo, for everybody
	code, out, _ := r.call("GET", "/brand", "none", nil)
	if code != 200 || out["logo"] != false || len(out["name"].(map[string]any)) != 0 {
		t.Fatalf("empty brand: %d %v", code, out)
	}
	// names: a language left empty falls back to the first set (zh, en, ja order)
	out = r.ok("PUT", "/v1/brand", map[string]any{"name": map[string]string{"en": " Acme Corp ", "ja": ""}})
	if n := out["name"].(map[string]any); n["en"] != "Acme Corp" || len(n) != 1 {
		t.Errorf("names: %v", n)
	}
	b := r.s.State().Brand
	if b.NameFor("ja") != "Acme Corp" || b.NameFor("zh") != "Acme Corp" || b.NameFor("en") != "Acme Corp" {
		t.Errorf("fallback: %q %q", b.NameFor("ja"), b.NameFor("zh"))
	}
	r.ok("PUT", "/v1/brand", map[string]any{"name": map[string]string{"zh": "某某公司", "en": "Acme Corp"}})
	if b := r.s.State().Brand; b.NameFor("ja") != "某某公司" || b.NameFor("en") != "Acme Corp" {
		t.Errorf("fallback to the first set: %q", b.NameFor("ja"))
	}
	if code, _, _ := r.call("PUT", "/v1/brand", "", map[string]any{"name": map[string]string{"fr": "x"}}); code != 400 {
		t.Errorf("unknown language: %d", code)
	}
	if code, _, _ := r.call("PUT", "/v1/brand", "", map[string]any{"name": map[string]string{"en": strings.Repeat("x", 61)}}); code != 400 {
		t.Errorf("too long: %d", code)
	}
	if code, _, _ := r.call("PUT", "/v1/brand", "", map[string]any{"name": map[string]string{"en": "a\x01b"}}); code != 400 {
		t.Errorf("control character: %d", code)
	}
	if code, _, _ := r.call("PUT", "/v1/brand", "none", map[string]any{"name": map[string]string{"en": "x"}}); code != 401 {
		t.Errorf("without a login: %d", code)
	}
	// the logo
	if code, out, _ := r.raw("PUT", "/v1/brand/logo", "image/png", tinyPNG, ""); code != 200 || out["logo"] != true || out["logo_type"] != "image/png" {
		t.Fatalf("png: %d %v", code, out)
	}
	tag := r.s.State().Brand.Tag()
	req := httptest.NewRequest("GET", "/brand/logo?v="+tag, nil)
	rec := httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), tinyPNG) || rec.Header().Get("ETag") == "" {
		t.Errorf("logo: %d %s %d bytes", rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
	}
	req.Header.Set("If-None-Match", rec.Header().Get("ETag"))
	rec = httptest.NewRecorder()
	r.h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("etag: %d", rec.Code)
	}
	// the settings carry it too (the page's general card)
	if st := r.ok("GET", "/v1/settings", nil); st["brand"].(map[string]any)["logo_tag"] != tag {
		t.Errorf("settings: %v", st["brand"])
	}
	// refused: a wrong type, a type that does not match, a too large file, an SVG with a script
	for _, c := range []struct {
		ctype string
		body  []byte
	}{
		{"text/plain", []byte("hello")},
		{"image/png", []byte("not a png")},
		{"image/png", append(append([]byte{}, tinyPNG...), bytes.Repeat([]byte{0}, brandLogoMax)...)},
		{"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)},
		{"image/svg+xml", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"></svg>`)},
		{"image/svg+xml", []byte(`<html><svg/></html>`)},
	} {
		if code, _, _ := r.raw("PUT", "/v1/brand/logo", c.ctype, c.body, ""); code != 400 {
			t.Errorf("%s %q: %d, want 400", c.ctype, c.body[:min(len(c.body), 30)], code)
		}
	}
	if b := r.s.State().Brand; !bytes.Equal(b.Logo, tinyPNG) {
		t.Error("a refused upload changed the logo")
	}
	// a good SVG
	svg := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><circle cx="5" cy="5" r="4" fill="#0a0"/></svg>`)
	if code, out, _ := r.raw("PUT", "/v1/brand/logo", "image/svg+xml; charset=utf-8", svg, ""); code != 200 || out["logo_type"] != "image/svg+xml" || out["logo_tag"] == tag {
		t.Errorf("svg: %d %v", code, out)
	}
	// removed
	if out := r.ok("DELETE", "/v1/brand/logo", nil); out["logo"] != false {
		t.Errorf("delete: %v", out)
	}
	rec = httptest.NewRecorder()
	r.h.ServeHTTP(rec, httptest.NewRequest("GET", "/brand/logo", nil))
	if rec.Code != 404 {
		t.Errorf("no logo: %d", rec.Code)
	}
}
