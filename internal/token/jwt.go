// Package token mints and verifies the platform session JWT. It is the SAME
// HS256 scheme the Service Constructor authenticates with: sub=userId, signed
// with the shared AUTH_JWT_SECRET, so a token minted here is accepted by the
// constructor's gateway without any additional exchange.
package token

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Minter issues and verifies session tokens over a shared HMAC secret.
type Minter struct {
	secret []byte
	ttl    time.Duration
}

// NewMinter builds a Minter. ttl bounds token lifetime (0 = no expiry).
func NewMinter(secret []byte, ttl time.Duration) *Minter {
	return &Minter{secret: secret, ttl: ttl}
}

// Mint returns a signed token for a user carrying the given roles.
func (m *Minter) Mint(userID string, roles []string, now time.Time) (string, error) {
	if len(roles) == 0 {
		roles = []string{"user"}
	}
	claims := jwt.MapClaims{
		"sub":   userID,
		"roles": roles,
		"iat":   now.Unix(),
	}
	if m.ttl > 0 {
		claims["exp"] = now.Add(m.ttl).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return s, nil
}

// Verify parses a token and returns its subject (userId).
func (m *Minter) Verify(tokenStr string) (string, error) {
	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		return m.secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !parsed.Valid {
		return "", fmt.Errorf("invalid token: %v", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("token missing sub")
	}
	return sub, nil
}
