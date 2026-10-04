package netx

import (
	"net"
	"testing"
)

func TestIsPublicIP(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{ip: "8.8.8.8", want: true},
		{ip: "2606:4700:4700::1111", want: true},
		{ip: "127.0.0.1"},
		{ip: "0.0.0.1"},
		{ip: "10.0.0.1"},
		{ip: "100.64.0.1"},
		{ip: "169.254.169.254"},
		{ip: "192.0.2.1"},
		{ip: "198.18.0.1"},
		{ip: "224.0.0.1"},
		{ip: "::1"},
		{ip: "fc00::1"},
		{ip: "fe80::1"},
		{ip: "2001:db8::1"},
		{ip: "2002:7f00:1::1"},
		{ip: "::ffff:127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := IsPublicIP(net.ParseIP(tt.ip)); got != tt.want {
				t.Fatalf("IsPublicIP(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}
