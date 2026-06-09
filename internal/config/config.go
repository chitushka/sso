package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	AppEnv string
	HTTP   HTTPConfig
	DB     DBConfig
	Auth   AuthConfig
	CORS   CORSConfig
}

type HTTPConfig struct{ Addr string }
type DBConfig struct{ URL string }
type AuthConfig struct {
	JWTSecret      string
	AccessTokenTTL time.Duration
	SessionTTL     time.Duration
}
type CORSConfig struct{ AllowedOrigins []string }

func Load() (Config, error) {
	_ = godotenv.Load()
	cfg := Config{
		AppEnv: getEnv("APP_ENV", "local"),
		HTTP:   HTTPConfig{Addr: getEnv("HTTP_ADDR", ":8080")},
		DB:     DBConfig{URL: os.Getenv("DATABASE_URL")},
		Auth: AuthConfig{
			JWTSecret:      os.Getenv("JWT_SECRET"),
			AccessTokenTTL: mustDuration(getEnv("ACCESS_TOKEN_TTL", "15m")),
			SessionTTL:     mustDuration(getEnv("SESSION_TTL", "720h")),
		},
		CORS: CORSConfig{AllowedOrigins: splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080"))},
	}
	if cfg.DB.URL == "" {
		return cfg, errors.New("DATABASE_URL is required")
	}
	if len(cfg.Auth.JWTSecret) < 32 {
		return cfg, errors.New("JWT_SECRET must contain at least 32 characters")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
func mustDuration(v string) time.Duration {
	d, err := time.ParseDuration(v)
	if err != nil {
		panic(err)
	}
	return d
}
func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
