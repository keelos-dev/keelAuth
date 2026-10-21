package auth

import (
	"net/http"
	"regexp"
	"time"
)

// Time zones (keelOS docs/47): keelauthd stores and sends UTC; the page shows times in the zone
// of the place, never in the browser's. Managed by keel that is keel's own setting: keel sends
// it with every request it passes through (X-Keel-Timezone), in the seed and in its answer to
// the registration (keelAuth's own LAN page uses that). Standalone it is keelAuth's setting
// (state.json timezone, the Settings page; default UTC).

// ZoneHeader is the header keel's /i/ proxy sets to its time zone.
const ZoneHeader = "X-Keel-Timezone"

var zoneRE = regexp.MustCompile(`^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+){0,2}$`)

// validZone: a zone name this keelauthd knows ("UTC" always).
func validZone(z string) bool {
	if z == "UTC" {
		return true
	}
	if z == "" || len(z) > 64 || !zoneRE.MatchString(z) {
		return false
	}
	_, err := time.LoadLocation(z)
	return err == nil
}

// SetKeelZone takes keel's zone (from its answer to the registration).
func (s *Server) SetKeelZone(z string) {
	if validZone(z) {
		if old, _ := s.keelTZ.Load().(string); old != z {
			s.keelTZ.Store(z)
			if old != "" {
				s.Log.Printf("time zone: keel's is %s now", z)
			}
		}
	}
}

// managed: there is a seed (keel manages this keelAuth).
func (s *Server) managed() bool {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	return s.seed != nil
}

// zoneFor is the zone the page shows times in for r.
func (s *Server) zoneFor(r *http.Request) string {
	if r != nil && caller(r).Kind == "keel" {
		if z := r.Header.Get(ZoneHeader); validZone(z) {
			return z
		}
	}
	if s.managed() {
		if z, _ := s.keelTZ.Load().(string); z != "" {
			return z
		}
		return "UTC"
	}
	if z := s.State().Timezone; validZone(z) {
		return z
	}
	return "UTC"
}
