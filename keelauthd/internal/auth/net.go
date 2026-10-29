package auth

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// The internal NIC (keelNAS docs/04 section 11): the NIC that connects keelAuth only with its
// keelOS host. It is found by the MAC the seed names and gets the seed's address, no DHCP.

// Iface is one network interface as ifconfig shows it.
type Iface struct {
	Name     string   `json:"name"`
	MAC      string   `json:"mac"`
	Up       bool     `json:"up"`
	Address  []string `json:"addresses"`
	Internal bool     `json:"internal,omitempty"`
}

var (
	ifHeadRE = regexp.MustCompile(`^([a-z][a-z0-9_.]*): flags=[0-9a-f]+<([^>]*)>`)
	macRE    = regexp.MustCompile(`^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`)
)

// parseIfconfig reads `ifconfig -a`: the Ethernet interfaces (those with an "ether" line).
func parseIfconfig(out string) []Iface {
	var all []Iface
	var cur *Iface
	for _, l := range strings.Split(out, "\n") {
		if m := ifHeadRE.FindStringSubmatch(l); m != nil {
			all = append(all, Iface{Name: m[1], Up: strings.Contains(","+m[2]+",", ",UP,"), Address: []string{}})
			cur = &all[len(all)-1]
			continue
		}
		if cur == nil {
			continue
		}
		f := strings.Fields(l)
		switch {
		case len(f) >= 2 && f[0] == "ether":
			cur.MAC = strings.ToLower(f[1])
		case len(f) >= 4 && f[0] == "inet" && f[2] == "netmask":
			ones := 0
			var mask uint64
			fmt.Sscanf(strings.TrimPrefix(f[3], "0x"), "%x", &mask)
			for b := mask; b != 0; b &= b - 1 {
				ones++
			}
			cur.Address = append(cur.Address, fmt.Sprintf("%s/%d", f[1], ones))
		}
	}
	var eth []Iface
	for _, i := range all {
		if i.MAC != "" {
			eth = append(eth, i)
		}
	}
	return eth
}

// internalIP is the internal link's address from the seed ("" without one).
func (s *Server) internalIP() string {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.seed == nil || s.seed.Internal == nil {
		return ""
	}
	ip, _, _ := net.ParseCIDR(s.seed.Internal.Address)
	if ip == nil {
		return ""
	}
	return ip.String()
}

func (s *Server) internalMAC() string {
	s.hmu.Lock()
	defer s.hmu.Unlock()
	if s.seed == nil || s.seed.Internal == nil {
		return ""
	}
	return s.seed.Internal.MAC
}

// ApplyInternal sets the internal NIC's address from the seed; no DHCP there.
func (s *Server) ApplyInternal() {
	s.hmu.Lock()
	sd := s.seed
	s.hmu.Unlock()
	if sd == nil || sd.Internal == nil {
		return
	}
	out, err := s.Sys.Run("", "ifconfig", "-a")
	if err != nil {
		s.Log.Printf("internal NIC: %v", err)
		return
	}
	for _, i := range parseIfconfig(out) {
		if i.MAC != sd.Internal.MAC {
			continue
		}
		s.Sys.Run("", "service", "dhclient", "stop", i.Name)
		if _, err := s.Sys.Run("", "ifconfig", i.Name, "inet", sd.Internal.Address, "up"); err != nil {
			s.Log.Printf("internal NIC %s: %v", i.Name, err)
			return
		}
		s.Log.Printf("internal NIC %s: %s", i.Name, sd.Internal.Address)
		return
	}
	s.Log.Printf("internal NIC: no interface with MAC %s", sd.Internal.MAC)
}

// ParseAddresses reads `ifconfig -a inet`: the IPv4 addresses of every interface but the
// loopback, the link-local internal one (169.254.x) left out.
func ParseAddresses(out string) []string {
	addrs := []string{}
	iface := ""
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		if line[0] != ' ' && line[0] != '\t' {
			if i := strings.IndexByte(line, ':'); i > 0 {
				iface = line[:i]
			}
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "inet" && !strings.HasPrefix(iface, "lo") && !strings.HasPrefix(f[1], "169.254.") {
			addrs = append(addrs, f[1])
		}
	}
	return addrs
}

// addresses are the VM's LAN addresses.
func (s *Server) addresses() []string {
	out, err := s.Sys.Run("", "ifconfig", "-a", "inet")
	if err != nil {
		return []string{}
	}
	return ParseAddresses(out)
}

func (s *Server) hostname() string {
	out, err := s.Sys.Run("", "sysctl", "-n", "kern.hostname")
	if err != nil || strings.TrimSpace(out) == "" {
		return "keelauth"
	}
	h := strings.TrimSpace(out)
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return strings.ToLower(h)
}

// versionString: the image's version (from /etc/keelauth-version) with keelauthd's.
func (s *Server) versionString() string {
	if b, err := s.Sys.ReadFile("/etc/keelauth-version"); err == nil {
		return strings.TrimSpace(string(b)) + " (keelauthd " + s.Version + ")"
	}
	return s.Version
}

// httpsPort is the LAN web page's port.
func (s *Server) httpsPort() int {
	_, p, err := net.SplitHostPort(s.State().HTTPSListen)
	if err != nil {
		return 443
	}
	n, _ := strconv.Atoi(p)
	return n
}

// redirectHandler sends every request to https:// on the same host, with httpsAddr's port when
// it is not 443 (as keel's).
func redirectHandler(httpsAddr string) http.Handler {
	_, port, _ := net.SplitHostPort(httpsAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
		if host == "" {
			http.Error(w, "use https", http.StatusBadRequest)
			return
		}
		if port != "" && port != "443" {
			host = net.JoinHostPort(host, port)
		} else if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			host = "[" + host + "]"
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}
