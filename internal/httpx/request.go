package httpx

import (
	"net"
	"net/http"
	"strings"
)

func IsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https")
}

// ClientIP возвращает нормализованный адрес клиента. Middleware RealIP заранее
// переносит доверенный X-Forwarded-For в RemoteAddr и удаляет исходный заголовок.
func ClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
