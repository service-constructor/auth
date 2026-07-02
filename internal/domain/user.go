// Package domain holds the auth service's core types and errors.
package domain

import (
	"errors"
	"time"
)

// User is a registered account. PasswordHash is a bcrypt hash and never leaves
// the service. Every user is provisioned a TON deposit wallet: in the demo all
// users share one on-chain address but get a unique DepositMemo, and their money
// is tracked in the ledger under WalletID.
type User struct {
	ID           string
	Login        string
	PasswordHash string
	TONAddress   string
	DepositMemo  string
	WalletID     string
	CreatedAt    time.Time
}

// Auth sentinel errors.
var (
	ErrLoginTaken      = errors.New("login already taken")
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidCreds    = errors.New("invalid login or password")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrMemoNotFound    = errors.New("no user for deposit memo")
	ErrInternal        = errors.New("internal error")
	// ErrRealCurrencyDeposit rejects a mock deposit for a real currency: real money
	// is funded only by the on-chain deposit watcher, never by the demo endpoint.
	ErrRealCurrencyDeposit = errors.New("mock deposit not allowed for a real currency")
)
