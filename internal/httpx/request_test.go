package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tests := []struct {
		remoteAddr string
		want       string
	}{
		{remoteAddr: "192.0.2.10:1234", want: "192.0.2.10"},
		{remoteAddr: "[2001:db8::1]:443", want: "2001:db8::1"},
		{remoteAddr: "192.0.2.10", want: "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.remoteAddr, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			r.Header.Set("X-Forwarded-For", "203.0.113.7")
			if got := ClientIP(r); got != tt.want {
				t.Fatalf("ClientIP() = %q, ожидалось %q", got, tt.want)
			}
		})
	}
}
