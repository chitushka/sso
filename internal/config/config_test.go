package config

import (
	"testing"
	"time"
)

func validProductionConfig() Config {
	return Config{
		Env:      "production",
		Database: DatabaseConfig{URL: "postgres://sso@db/sso?sslmode=require"},
		Security: SecurityConfig{
			JWTSecret:     "jwt-secret-that-is-at-least-32-bytes",
			EncryptionKey: "encryption-key-that-is-at-least-32",
		},
		Token: TokenConfig{AccessTTL: 15 * time.Minute, SessionTTL: 24 * time.Hour, RefreshTTL: 24 * time.Hour},
		CORS:  CORSConfig{AllowedOrigins: []string{"https://sso.example.com"}},
		OIDC:  OIDCConfig{Issuer: "https://sso.example.com"},
		SMTP:  SMTPConfig{Host: "smtp.example.com", Port: 587, From: "sso@example.com", StartTLS: true},
	}
}

func TestProductionConfigIsAccepted(t *testing.T) {
	if err := validProductionConfig().Validate(); err != nil {
		t.Fatalf("valid production config: %v", err)
	}
}

func TestProductionConfigFailsClosed(t *testing.T) {
	tests := map[string]func(*Config){
		"http issuer":          func(c *Config) { c.OIDC.Issuer = "http://sso.example.com" },
		"database without tls": func(c *Config) { c.Database.URL = "postgres://sso@db/sso?sslmode=disable" },
		"database tls omitted": func(c *Config) { c.Database.URL = "postgres://sso@db/sso" },
		"database tls prefer":  func(c *Config) { c.Database.URL = "postgres://sso@db/sso?sslmode=prefer" },
		"equal secrets":        func(c *Config) { c.Security.EncryptionKey = c.Security.JWTSecret },
		"placeholder secret":   func(c *Config) { c.Security.JWTSecret = "change-me-please-change-me-please" },
		"missing smtp":         func(c *Config) { c.SMTP = SMTPConfig{Port: 587, StartTLS: true} },
		"smtp without tls":     func(c *Config) { c.SMTP.StartTLS = false },
		"invalid proxy":        func(c *Config) { c.HTTPSecurity.TrustedProxies = []string{"not-an-ip"} },
		"credential without tls": func(c *Config) {
			c.SMTP.Username = "user"
			c.SMTP.Password = "secret"
			c.SMTP.StartTLS = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validProductionConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
