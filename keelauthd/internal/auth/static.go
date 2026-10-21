package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"io/fs"
	"net/http"
	"regexp"
	"strings"

	"keelauth/internal/web"
)

var inlineScriptRE = regexp.MustCompile(`(?s)<script type="importmap">(.*?)</script>`)

// scriptHashes are the CSP hashes of index.html's inline scripts (the import map), as keel does.
func scriptHashes(sub fs.FS) string {
	b, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return ""
	}
	var out []string
	for _, m := range inlineScriptRE.FindAllSubmatch(b, -1) {
		sum := sha256.Sum256(m[1])
		out = append(out, "'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'")
	}
	return strings.Join(out, " ")
}

// static serves the web page. index.html and the scripts are revalidated every time (a new
// keelauthd brings new ones); the vendored libraries are cached.
func (s *Server) static() http.Handler {
	sub, _ := fs.Sub(web.Static, "static")
	fsrv := http.FileServer(http.FS(sub))
	csp := "default-src 'self'; script-src 'self' " + scriptHashes(sub) + "; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
		"frame-ancestors 'self'; base-uri 'none'; form-action 'self'"
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasSuffix(p, "/") && p != "/" {
			http.NotFound(w, r) // no directory listings
			return
		}
		if strings.HasPrefix(p, "/vendor/") {
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		w.Header().Set("Content-Security-Policy", csp)
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		fsrv.ServeHTTP(w, r)
	})
}
