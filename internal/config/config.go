package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	HTTP HTTPConfig
	DB   DBConfig
	Auth AuthConfig
	CORS CORSConfig
	OIDC OIDCConfig
}
type HTTPConfig struct{ Addr string }
type DBConfig struct{ URL string }
type AuthConfig struct {
	JWTSecret      string
	AccessTokenTTL time.Duration
	SessionTTL     time.Duration
}
type CORSConfig struct{ AllowedOrigins []string }
type OIDCConfig struct {
	Issuer             string
	KeyRotationEnabled bool
}

func Load() (Config, error) {
	_ = godotenv.Load()
	return Config{
		HTTP: HTTPConfig{Addr: env("SSO_HTTP_ADDR", ":8080")},
		DB:   DBConfig{URL: env("SSO_DB_URL", "postgres://sso:sso@localhost:5432/sso?sslmode=disable")},
		Auth: AuthConfig{JWTSecret: env("SSO_JWT_SECRET", "dev-secret-change-me"), AccessTokenTTL: dur("SSO_ACCESS_TOKEN_TTL", 15*time.Minute), SessionTTL: dur("SSO_SESSION_TTL", 24*time.Hour)},
		CORS: CORSConfig{AllowedOrigins: split(env("SSO_CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:8080"))},
		OIDC: OIDCConfig{Issuer: env("SSO_ISSUER", "http://localhost:8080"), KeyRotationEnabled: boolean("SSO_OIDC_KEY_ROTATION_ENABLED", false)},
	}, nil
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func split(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
func dur(k string, d time.Duration) time.Duration {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	x, err := time.ParseDuration(v)
	if err != nil {
		return d
	}
	return x
}
func boolean(k string, d bool) bool {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return d
	}
	return b
}
