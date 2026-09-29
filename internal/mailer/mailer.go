package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// Mailer sends transactional mail (password reset, email verification).
type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

func (c Config) Enabled() bool { return c.Host != "" && c.From != "" }

// New returns an SMTP mailer when configured, otherwise a disabled mailer that
// logs only non-sensitive delivery metadata.
func New(cfg Config, logger *slog.Logger) Mailer {
	if cfg.Enabled() {
		return &SMTPMailer{cfg: cfg}
	}
	return &DisabledMailer{logger: logger}
}

type SMTPMailer struct{ cfg Config }

func (m *SMTPMailer) Send(ctx context.Context, to, subject, body string) error {
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	from, err := mail.ParseAddress(m.cfg.From)
	if err != nil {
		return errors.New("invalid SMTP sender address")
	}
	recipient, err := mail.ParseAddress(to)
	if err != nil || recipient.Address != to || strings.ContainsAny(subject, "\r\n") {
		return errors.New("invalid SMTP recipient or subject")
	}

	msg := strings.Join([]string{
		"From: " + from.String(),
		"To: " + recipient.String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	dialer := net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = conn.Close()
		return err
	}
	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer func() { _ = c.Close() }()
	if m.cfg.StartTLS {
		if err := c.StartTLS(&tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	}
	if m.cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(recipient.Address); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// DisabledMailer is used in development when SMTP is not configured. Message
// bodies are deliberately discarded because they contain recovery credentials.
type DisabledMailer struct{ logger *slog.Logger }

func (m *DisabledMailer) Send(_ context.Context, to, subject, _ string) error {
	m.logger.Warn("smtp disabled, mail not sent", "to", to, "subject", subject)
	return errors.New("smtp is not configured")
}
