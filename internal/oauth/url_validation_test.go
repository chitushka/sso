package oauth

import (
	"errors"
	"testing"
)

func TestValidateClientURLs(t *testing.T) {
	tests := []struct {
		name        string
		clientType  ClientType
		redirect    string
		postLogout  string
		backchannel string
		wantErr     bool
	}{
		{name: "confidential HTTPS", clientType: ClientConfidential, redirect: "https://client.example/callback", postLogout: "https://client.example/logout", backchannel: "https://client.example/backchannel"},
		{name: "public HTTPS", clientType: ClientPublic, redirect: "https://client.example/callback"},
		{name: "public IPv4 loopback HTTP", clientType: ClientPublic, redirect: "http://127.0.0.1:49152/callback"},
		{name: "public IPv6 loopback HTTP", clientType: ClientPublic, redirect: "http://[::1]:49152/callback"},
		{name: "confidential HTTP", clientType: ClientConfidential, redirect: "http://client.example/callback", wantErr: true},
		{name: "public non-loopback HTTP", clientType: ClientPublic, redirect: "http://client.example/callback", wantErr: true},
		{name: "public localhost HTTP", clientType: ClientPublic, redirect: "http://localhost:49152/callback", wantErr: true},
		{name: "dangerous scheme", clientType: ClientPublic, redirect: "javascript:alert(1)", wantErr: true},
		{name: "redirect fragment", clientType: ClientConfidential, redirect: "https://client.example/callback#fragment", wantErr: true},
		{name: "redirect userinfo", clientType: ClientConfidential, redirect: "https://user@client.example/callback", wantErr: true},
		{name: "post logout fragment", clientType: ClientConfidential, redirect: "https://client.example/callback", postLogout: "https://client.example/logout#fragment", wantErr: true},
		{name: "backchannel HTTP", clientType: ClientConfidential, redirect: "https://client.example/callback", backchannel: "http://client.example/backchannel", wantErr: true},
		{name: "backchannel loopback", clientType: ClientConfidential, redirect: "https://client.example/callback", backchannel: "https://127.0.0.1/backchannel", wantErr: true},
		{name: "backchannel private", clientType: ClientConfidential, redirect: "https://client.example/callback", backchannel: "https://10.0.0.1/backchannel", wantErr: true},
		{name: "backchannel metadata", clientType: ClientConfidential, redirect: "https://client.example/callback", backchannel: "https://169.254.169.254/latest/meta-data", wantErr: true},
		{name: "backchannel localhost", clientType: ClientConfidential, redirect: "https://client.example/callback", backchannel: "https://service.localhost/backchannel", wantErr: true},
		{name: "unsupported client type", clientType: ClientType("other"), redirect: "https://client.example/callback", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var postLogout []string
			if tt.postLogout != "" {
				postLogout = []string{tt.postLogout}
			}
			err := validateClientURLs(tt.clientType, []string{tt.redirect}, postLogout, tt.backchannel)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateClientURLs() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidClientMetadata) {
				t.Fatalf("error must wrap ErrInvalidClientMetadata: %v", err)
			}
		})
	}
}

func TestUpdateClientValidatesUsingStoredClientType(t *testing.T) {
	client := confidentialClient()
	svc, repo, _, _ := setup(t, client)
	_, err := svc.UpdateClient(t.Context(), client.ID, UpdateClientInput{RedirectURIs: []string{"http://127.0.0.1:49152/callback"}})
	if !errors.Is(err, ErrInvalidClientMetadata) {
		t.Fatalf("expected metadata validation error, got %v", err)
	}
	stored, findErr := repo.FindClientByID(t.Context(), client.ID)
	if findErr != nil {
		t.Fatal(findErr)
	}
	if stored.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatal("invalid update reached the repository")
	}
}

func TestCreateClientRejectsInvalidURLBeforePersistence(t *testing.T) {
	svc, repo, _, _ := setup(t, confidentialClient())
	_, err := svc.CreateClient(t.Context(), CreateClientInput{ClientID: "invalid", Type: ClientConfidential, RedirectURIs: []string{"file:///tmp/callback"}})
	if !errors.Is(err, ErrInvalidClientMetadata) {
		t.Fatalf("expected metadata validation error, got %v", err)
	}
	if _, ok := repo.clients["invalid"]; ok {
		t.Fatal("invalid client was persisted")
	}
}
