package mailer

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/smtp"
	"strconv"
	"strings"
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

// New returns an SMTP mailer when configured, otherwise a logger fallback
// that writes the mail to the application log (dev mode).
func New(cfg Config, logger *slog.Logger) Mailer {
	if cfg.Enabled() {
		return &SMTPMailer{cfg: cfg}
	}
	return &LogMailer{logger: logger}
}

type SMTPMailer struct{ cfg Config }

func (m *SMTPMailer) Send(_ context.Context, to, subject, body string) error {
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	msg := strings.Join([]string{
		"From: " + m.cfg.From,
		"To: " + to,
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
		"",
		body,
	}, "\r\n")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
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
	if err := c.Mail(m.cfg.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
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

// LogMailer is the dev fallback when SMTP is not configured: the message
// (including reset/verification links) goes to the JSON log.
type LogMailer struct{ logger *slog.Logger }

func (m *LogMailer) Send(_ context.Context, to, subject, body string) error {
	m.logger.Info("smtp disabled, mail logged instead", "to", to, "subject", subject, "body", body)
	return nil
}
