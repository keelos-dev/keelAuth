package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRedirectHandler(t *testing.T) {
	for _, c := range []struct{ https, host, uri, want string }{
		{":443", "192.168.1.20", "/", "https://192.168.1.20/"},
		{":443", "192.168.1.20:80", "/", "https://192.168.1.20/"},
		{":443", "auth.example.lan", "/v1/users?x=1", "https://auth.example.lan/v1/users?x=1"},
		{":2291", "auth.example.lan", "/", "https://auth.example.lan:2291/"},
		{":443", "[fd00::5]:80", "/", "https://[fd00::5]/"},
	} {
		r := httptest.NewRequest("GET", "http://"+c.host+c.uri, nil)
		r.Host = c.host
		w := httptest.NewRecorder()
		redirectHandler(c.https).ServeHTTP(w, r)
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != c.want {
			t.Errorf("%s %s%s: %d %s (want %s)", c.https, c.host, c.uri, w.Code, w.Header().Get("Location"), c.want)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "http://x/", nil)
	r.Host = ""
	redirectHandler(":443").ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("no host: %d", w.Code)
	}
}
