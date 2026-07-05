package middleware

import (
	"net"
	"net/http"
	"strings"
)

// RealIP normalizes the client IP so downstream handlers can trust it.
//
// X-Forwarded-For is only honored when the immediate peer (RemoteAddr) is a
// configured trusted proxy; otherwise the header is stripped so a client cannot
// spoof its IP to evade per-IP brute-force lockout and rate limiting. The
// resolved client IP is written back into RemoteAddr, and X-Forwarded-For is
// removed either way, so the existing clientIP helpers fall back to RemoteAddr.
func RealIP(trustedProxies []string) func(http.Handler) http.Handler {
	nets := parseCIDRs(trustedProxies)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := hostOnly(r.RemoteAddr)
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" && ipInAny(peer, nets) {
				if client := rightmostUntrusted(xff, nets); client != "" {
					r.RemoteAddr = net.JoinHostPort(client, "0")
				}
			}
			r.Header.Del("X-Forwarded-For")
			next.ServeHTTP(w, r)
		})
	}
}

func parseCIDRs(entries []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			if strings.Contains(e, ":") {
				e += "/128"
			} else {
				e += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func ipInAny(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// rightmostUntrusted returns the last X-Forwarded-For entry that is not itself
// a trusted proxy — the real client as seen by the outermost trusted hop.
func rightmostUntrusted(xff string, nets []*net.IPNet) string {
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(parts[i])
		if ip != "" && !ipInAny(ip, nets) {
			return ip
		}
	}
	return ""
}
