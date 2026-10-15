package mailer

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestNewSelectsMailerFromConfiguration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, ok := New(Config{}, logger).(*DisabledMailer); !ok {
		t.Fatal("без SMTP должен использоваться DisabledMailer")
	}
	if _, ok := New(Config{Host: "smtp.example.org", Port: 587, From: "sso@example.org"}, logger).(*SMTPMailer); !ok {
		t.Fatal("при полной конфигурации должен использоваться SMTPMailer")
	}
}

func TestSMTPMailerRejectsHeaderInjectionBeforeConnecting(t *testing.T) {
	m := &SMTPMailer{cfg: Config{Host: "smtp.example.org", Port: 587, From: "sso@example.org"}}
	err := m.Send(context.Background(), "user@example.org", "Тема\r\nBcc: attacker@example.org", "body")
	if err == nil || !strings.Contains(err.Error(), "invalid SMTP recipient or subject") {
		t.Fatalf("инъекция заголовка не отклонена: %v", err)
	}
}
