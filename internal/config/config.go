// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all runtime settings.
type Config struct {
	// DatabaseURL is the Postgres DSN.
	DatabaseURL string
	// GRPCAddr is the listen address for the gRPC server.
	GRPCAddr string
	// HTTPAddr is the listen address for the HTTP gateway.
	HTTPAddr string
	// JWTSecret signs session tokens; it MUST match the constructor's
	// AUTH_JWT_SECRET so tokens minted here are accepted there.
	JWTSecret string
	// TokenTTL bounds session lifetime.
	TokenTTL time.Duration
	// LedgerAddr is the ledger gRPC endpoint (host:port).
	LedgerAddr string
	// DefaultCurrencyID is the currency the registration wallet is provisioned for.
	DefaultCurrencyID int64
	// SuperAdminLogins are granted the super_admin role (see all owners' services
	// in the admin console). Set manually; comma-separated in SUPER_ADMIN_LOGINS.
	SuperAdminLogins []string
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
}

// Load reads configuration from the environment, applying defaults.
func Load() (Config, error) {
	c := Config{
		DatabaseURL:       env("DATABASE_URL", "postgres://sc:sc@localhost:5432/auth?sslmode=disable"),
		GRPCAddr:          env("GRPC_ADDR", ":9200"),
		HTTPAddr:          env("HTTP_ADDR", ":8090"),
		JWTSecret:         env("AUTH_JWT_SECRET", "devsecret"),
		TokenTTL:          24 * time.Hour,
		LedgerAddr:        env("LEDGER_ADDR", "localhost:9110"),
		DefaultCurrencyID: 1,
		SuperAdminLogins:  splitList(env("SUPER_ADMIN_LOGINS", "")),
		ShutdownTimeout:   10 * time.Second,
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("DATABASE_URL is required")
	}
	if c.JWTSecret == "" {
		return Config{}, fmt.Errorf("AUTH_JWT_SECRET is required")
	}
	return c, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// splitList parses a comma-separated env value into a trimmed, non-empty slice.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
