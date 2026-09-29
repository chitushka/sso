package httpx

import (
	"net/http"
	"strings"
)

func IsHTTPS(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.URL.Scheme, "https")
}
