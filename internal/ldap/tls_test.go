package ldap

import (
	"errors"
	"testing"
)

func TestValidateProviderTransport(t *testing.T) {
	tests := []struct {
		name       string
		provider   Provider
		requireTLS bool
		want       error
	}{
		{name: "development plaintext", provider: Provider{}, requireTLS: false},
		{name: "production LDAPS", provider: Provider{UseTLS: true}, requireTLS: true},
		{name: "production StartTLS", provider: Provider{StartTLS: true}, requireTLS: true},
		{name: "production plaintext rejected", provider: Provider{}, requireTLS: true, want: ErrTLSRequired},
		{name: "conflicting modes rejected", provider: Provider{UseTLS: true, StartTLS: true}, requireTLS: true, want: ErrConflictingTLSModes},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateProviderTransport(tt.provider, tt.requireTLS)
			if tt.want == nil && err != nil {
				t.Fatal(err)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}
}

func TestProductionClientRejectsPlainLDAPBeforeDial(t *testing.T) {
	client := NewClient().WithTLSRequired(true)
	conn, err := client.dial(Provider{Host: "127.0.0.1", Port: 389})
	if conn != nil {
		_ = conn.Close()
		t.Fatal("unexpected plaintext LDAP connection")
	}
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("got %v, want ErrTLSRequired", err)
	}
}
