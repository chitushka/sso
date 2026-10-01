package config

import (
	"errors"
	"fmt"
	"net"
	stdmail "net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Env          string
	HTTP         HTTPConfig
	Database     DatabaseConfig
	Security     SecurityConfig
	Token        TokenConfig
	CORS         CORSConfig
	OIDC         OIDCConfig
	Logging      LoggingConfig
	SMTP         SMTPConfig
	HTTPSecurity HTTPSecurityConfig
}

type HTTPConfig struct {
	Address string
}

type DatabaseConfig struct {
	URL            string
	MigrateOnStart bool
}

type SecurityConfig struct {
	JWTSecret     string
	EncryptionKey string
}

type TokenConfig struct {
	AccessTTL  time.Duration
	SessionTTL time.Duration
	RefreshTTL time.Duration
}

type CORSConfig struct {
	AllowedOrigins []string
}

type HTTPSecurityConfig struct {
	TrustedProxies []string
}

type OIDCConfig struct {
	Issuer string
}

type LoggingConfig struct {
	Level string
}

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	StartTLS bool
}

func Load() (Config, error) {
	_ = godotenv.Load()

	var parseErrs []error
	duration := func(key string, defaultValue time.Duration) time.Duration {
		v, err := parseDuration(key, defaultValue)
		if err != nil {
			parseErrs = append(parseErrs, err)
		}
		return v
	}
	boolean := func(key string, defaultValue bool) bool {
		v, err := parseBoolean(key, defaultValue)
		if err != nil {
			parseErrs = append(parseErrs, err)
		}
		return v
	}
	integer := func(key string, defaultValue int) int {
		v, err := parseInteger(key, defaultValue)
		if err != nil {
			parseErrs = append(parseErrs, err)
		}
		return v
	}

	runtimeEnv := strings.ToLower(env("SSO_ENV", "local"))
	defaultOrigins := ""
	if isDevelopment(runtimeEnv) {
		defaultOrigins = "http://localhost:5173,http://localhost:8080"
	}

	cfg := Config{
		Env: runtimeEnv,
		HTTP: HTTPConfig{
			Address: env("SSO_HTTP_ADDR", ":8080"),
		},
		Database: DatabaseConfig{
			URL:            os.Getenv("SSO_DATABASE_URL"),
			MigrateOnStart: boolean("SSO_MIGRATE_ON_START", false),
		},
		Security: SecurityConfig{
			JWTSecret:     os.Getenv("SSO_JWT_SECRET"),
			EncryptionKey: os.Getenv("SSO_ENCRYPTION_KEY"),
		},
		Token: TokenConfig{
			AccessTTL:  duration("SSO_ACCESS_TOKEN_TTL", 15*time.Minute),
			SessionTTL: duration("SSO_SESSION_TTL", 720*time.Hour),
			RefreshTTL: duration("SSO_REFRESH_TOKEN_TTL", 720*time.Hour),
		},
		CORS: CORSConfig{
			AllowedOrigins: split(env("SSO_CORS_ALLOWED_ORIGINS", defaultOrigins)),
		},
		OIDC: OIDCConfig{
			Issuer: env("SSO_ISSUER", "http://localhost:8080"),
		},
		Logging: LoggingConfig{
			Level: env("SSO_LOG_LEVEL", "info"),
		},
		HTTPSecurity: HTTPSecurityConfig{
			TrustedProxies: split(os.Getenv("SSO_TRUSTED_PROXIES")),
		},
		SMTP: SMTPConfig{
			Host:     os.Getenv("SSO_SMTP_HOST"),
			Port:     integer("SSO_SMTP_PORT", 587),
			Username: os.Getenv("SSO_SMTP_USERNAME"),
			Password: os.Getenv("SSO_SMTP_PASSWORD"),
			From:     os.Getenv("SSO_SMTP_FROM"),
			StartTLS: boolean("SSO_SMTP_STARTTLS", true),
		},
	}

	if err := errors.Join(parseErrs...); err != nil {
		return Config{}, err
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	var errs []error

	databaseURL, databaseErr := url.Parse(c.Database.URL)
	if strings.TrimSpace(c.Database.URL) == "" {
		errs = append(errs, errors.New("SSO_DATABASE_URL is required"))
	} else if databaseErr != nil || databaseURL.Host == "" || (databaseURL.Scheme != "postgres" && databaseURL.Scheme != "postgresql") {
		errs = append(errs, errors.New("SSO_DATABASE_URL must be an absolute PostgreSQL URL"))
	}
	if strings.TrimSpace(c.Security.JWTSecret) == "" {
		errs = append(errs, errors.New("SSO_JWT_SECRET is required"))
	}
	if len(c.Security.JWTSecret) > 0 && len(c.Security.JWTSecret) < 32 {
		errs = append(errs, errors.New("SSO_JWT_SECRET must be at least 32 characters"))
	}
	if strings.TrimSpace(c.Security.EncryptionKey) == "" {
		errs = append(errs, errors.New("SSO_ENCRYPTION_KEY is required"))
	}
	if len(c.Security.EncryptionKey) > 0 && len(c.Security.EncryptionKey) < 32 {
		errs = append(errs, errors.New("SSO_ENCRYPTION_KEY must be at least 32 characters"))
	}
	if strings.TrimSpace(c.OIDC.Issuer) == "" {
		errs = append(errs, errors.New("SSO_ISSUER is required"))
	}
	if c.Token.AccessTTL <= 0 {
		errs = append(errs, errors.New("SSO_ACCESS_TOKEN_TTL must be positive"))
	}
	if c.Token.SessionTTL <= 0 {
		errs = append(errs, errors.New("SSO_SESSION_TTL must be positive"))
	}
	if c.Token.RefreshTTL <= 0 {
		errs = append(errs, errors.New("SSO_REFRESH_TOKEN_TTL must be positive"))
	}

	if c.Security.JWTSecret != "" && c.Security.JWTSecret == c.Security.EncryptionKey {
		errs = append(errs, errors.New("SSO_JWT_SECRET and SSO_ENCRYPTION_KEY must be different"))
	}

	production := !isDevelopment(c.Env)
	issuer, issuerErr := url.Parse(c.OIDC.Issuer)
	if issuerErr != nil || !issuer.IsAbs() || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		errs = append(errs, errors.New("SSO_ISSUER must be an absolute HTTP(S) URL without user info, query or fragment"))
	} else if issuer.Scheme != "http" && issuer.Scheme != "https" {
		errs = append(errs, errors.New("SSO_ISSUER must use http or https"))
	} else if production && issuer.Scheme != "https" {
		errs = append(errs, errors.New("SSO_ISSUER must use https outside development"))
	}

	if production {
		if strings.Contains(strings.ToLower(c.Security.JWTSecret), "change-me") || strings.Contains(strings.ToLower(c.Security.EncryptionKey), "change-me") {
			errs = append(errs, errors.New("placeholder secrets are forbidden outside development"))
		}
		if databaseErr == nil {
			switch strings.ToLower(databaseURL.Query().Get("sslmode")) {
			case "require", "verify-ca", "verify-full":
			default:
				errs = append(errs, errors.New("SSO_DATABASE_URL must explicitly require PostgreSQL TLS outside development (sslmode=require, verify-ca, or verify-full)"))
			}
		}
	}

	for _, origin := range c.CORS.AllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			errs = append(errs, fmt.Errorf("invalid CORS origin %q", origin))
		}
	}
	for _, proxy := range c.HTTPSecurity.TrustedProxies {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				errs = append(errs, fmt.Errorf("invalid trusted proxy %q", proxy))
			}
		}
	}

	smtpConfigured := c.SMTP.Host != "" || c.SMTP.From != "" || c.SMTP.Username != "" || c.SMTP.Password != ""
	if production && !smtpConfigured {
		errs = append(errs, errors.New("SMTP is required outside development"))
	}
	if smtpConfigured {
		if c.SMTP.Host == "" || c.SMTP.From == "" {
			errs = append(errs, errors.New("SSO_SMTP_HOST and SSO_SMTP_FROM are required together"))
		}
		if _, err := stdmail.ParseAddress(c.SMTP.From); c.SMTP.From != "" && err != nil {
			errs = append(errs, errors.New("SSO_SMTP_FROM must be a valid email address"))
		}
		if (c.SMTP.Username == "") != (c.SMTP.Password == "") {
			errs = append(errs, errors.New("SSO_SMTP_USERNAME and SSO_SMTP_PASSWORD are required together"))
		}
		if c.SMTP.Username != "" && !c.SMTP.StartTLS {
			errs = append(errs, errors.New("SMTP authentication requires STARTTLS"))
		}
	}
	if c.SMTP.Port < 1 || c.SMTP.Port > 65535 {
		errs = append(errs, errors.New("SSO_SMTP_PORT must be between 1 and 65535"))
	}

	return errors.Join(errs...)
}

func isDevelopment(environment string) bool {
	switch strings.ToLower(strings.TrimSpace(environment)) {
	case "local", "development", "dev", "test":
		return true
	default:
		return false
	}
}

func env(key string, defaultValue string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return defaultValue
}

func split(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseDuration(key string, defaultValue time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue, fmt.Errorf("%s has invalid duration %q: %w", key, value, err)
	}

	return parsed, nil
}

func parseInteger(key string, defaultValue int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue, fmt.Errorf("%s has invalid integer %q: %w", key, value, err)
	}

	return parsed, nil
}

func parseBoolean(key string, defaultValue bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue, nil
	}

	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue, fmt.Errorf("%s has invalid boolean %q: %w", key, value, err)
	}

	return parsed, nil
}
