package broker

import (
	"context"
	"net/http"
	"testing"
)

func TestBrokerUsesSafeOutboundClient(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, "https://sso.example.org", []byte("test-state-secret"))
	transport, ok := svc.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("неожиданный тип HTTP transport")
	}
	if transport.Proxy != nil || svc.client.CheckRedirect == nil {
		t.Fatal("broker должен отключать proxy и redirects")
	}
	_, err := svc.fetchIdentity(context.Background(), Provider{
		Code:         "private-idp",
		ClientID:     "client",
		ClientSecret: "secret",
		TokenURL:     "https://127.0.0.1/token",
		UserinfoURL:  "https://127.0.0.1/userinfo",
	}, "code")
	if err == nil {
		t.Fatal("broker выполнил запрос к loopback-адресу")
	}
}
