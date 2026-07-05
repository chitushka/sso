package config

import (
	"errors"
	"fmt"
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
	Issuer             string
	KeyRotationEnabled bool
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

	cfg := Config{
		Env: env("SSO_ENV", "local"),
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
			AllowedOrigins: split(env("SSO_CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:8080")),
		},
		OIDC: OIDCConfig{
			Issuer:             env("SSO_ISSUER", "http://localhost:8080"),
			KeyRotationEnabled: boolean("SSO_OIDC_KEY_ROTATION_ENABLED", false),
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

	if strings.TrimSpace(c.Database.URL) == "" {
		errs = append(errs, errors.New("SSO_DATABASE_URL is required"))
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

	return errors.Join(errs...)
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
