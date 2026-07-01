// Package service holds the auth application logic: registration, login, session
// issuance, and the demo deposit-by-memo path. It owns users; the wallet and its
// on-chain deposit routing are provisioned in the ledger service.
package service

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/nvsces/auth/internal/domain"
)

// LedgerAccount is the ledger's view of a provisioned account, returned to auth
// at registration.
type LedgerAccount struct {
	WalletID   string
	TONAddress string
	Memo       string
}

// Balance is a wallet's available/held for a currency, as reported by the ledger.
type Balance struct {
	Available string
	Held      string
}

// LedgerClient is the port to the ledger service. The gRPC client adapter
// implements it; tests use a fake.
type LedgerClient interface {
	// CreateAccount provisions (or returns) a user's ledger account.
	CreateAccount(ctx context.Context, userID string, currencyID int64) (*LedgerAccount, error)
	// CreditByMemo resolves the account by memo and credits a deposit; returns the
	// owning user's wallet and whether the credit was applied (false on replay).
	CreditByMemo(ctx context.Context, memo, ref, amount string, currencyID int64) (userID string, applied bool, err error)
	// GetBalance returns a wallet's current available/held for a currency.
	GetBalance(ctx context.Context, walletID string, currencyID int64) (*Balance, error)
}

// AccountView is a user's account plus its live balance, for the cabinet.
type AccountView struct {
	WalletID    string
	CurrencyID  int64
	TONAddress  string
	DepositMemo string
	Available   string
	Held        string
}

// TokenMinter issues session tokens carrying the given roles.
type TokenMinter interface {
	Mint(userID string, roles []string, now time.Time) (string, error)
}

// Store persists users.
type Store interface {
	Create(ctx context.Context, u *domain.User) error
	ByLogin(ctx context.Context, login string) (*domain.User, error)
	ByID(ctx context.Context, id string) (*domain.User, error)
}

// Auth is the application service.
type Auth struct {
	store       Store
	ledger      LedgerClient
	tokens      TokenMinter
	now         func() time.Time
	walletCcyID int64
	// superAdmins is the set of logins (lowercased) granted the super_admin role,
	// which sees every account's services in the admin console. Set manually.
	superAdmins map[string]bool
}

// Option configures an Auth.
type Option func(*Auth)

// WithClock overrides the time source (tests).
func WithClock(c func() time.Time) Option { return func(a *Auth) { a.now = c } }

// WithSuperAdmins marks the given logins as super-admins (case-insensitive).
func WithSuperAdmins(logins []string) Option {
	return func(a *Auth) {
		for _, l := range logins {
			l = strings.ToLower(strings.TrimSpace(l))
			if l != "" {
				a.superAdmins[l] = true
			}
		}
	}
}

// New builds an Auth service. defaultCurrencyID is the currency the registration
// wallet is provisioned for.
func New(store Store, ledger LedgerClient, tokens TokenMinter, defaultCurrencyID int64, opts ...Option) *Auth {
	a := &Auth{
		store:       store,
		ledger:      ledger,
		tokens:      tokens,
		now:         func() time.Time { return time.Now().UTC() },
		walletCcyID: defaultCurrencyID,
		superAdmins: map[string]bool{},
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Register creates a user, provisions their ledger account, issues a token.
func (a *Auth) Register(ctx context.Context, login, password string) (string, *domain.User, error) {
	login = strings.TrimSpace(login)
	if login == "" || len(password) < 6 {
		return "", nil, domain.ErrInvalidArgument
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}
	now := a.now()
	u := &domain.User{
		ID:           "usr_" + strings.ReplaceAll(uuid.NewString(), "-", ""),
		Login:        login,
		PasswordHash: string(hash),
		CreatedAt:    now,
	}

	// Provision the ledger account (wallet + TON deposit routing) and cache the
	// returned fields on the user for display.
	acc, err := a.ledger.CreateAccount(ctx, u.ID, a.walletCcyID)
	if err != nil {
		return "", nil, err
	}
	u.WalletID = acc.WalletID
	u.TONAddress = acc.TONAddress
	u.DepositMemo = acc.Memo

	if err := a.store.Create(ctx, u); err != nil {
		return "", nil, err
	}
	tok, err := a.tokens.Mint(u.ID, a.rolesFor(u.Login), now)
	if err != nil {
		return "", nil, err
	}
	return tok, u, nil
}

// rolesFor returns the roles a login's token carries. Every user is a tenant
// admin (can manage their own services in the admin console); a login in the
// super-admins set additionally gets super_admin (sees all owners).
func (a *Auth) rolesFor(login string) []string {
	roles := []string{"user", "admin"}
	if a.superAdmins[strings.ToLower(login)] {
		roles = append(roles, "super_admin")
	}
	return roles
}

// Login authenticates a user and issues a fresh token.
func (a *Auth) Login(ctx context.Context, login, password string) (string, *domain.User, error) {
	u, err := a.store.ByLogin(ctx, login)
	if err != nil {
		// Do not leak whether the login exists.
		return "", nil, domain.ErrInvalidCreds
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", nil, domain.ErrInvalidCreds
	}
	tok, err := a.tokens.Mint(u.ID, a.rolesFor(u.Login), a.now())
	if err != nil {
		return "", nil, err
	}
	return tok, u, nil
}

// Me returns the user for an authenticated session id.
func (a *Auth) Me(ctx context.Context, userID string) (*domain.User, error) {
	if userID == "" {
		return nil, domain.ErrUnauthenticated
	}
	return a.store.ByID(ctx, userID)
}

// ListAccounts returns the user's accounts with live balances from the ledger.
// In the demo a user has one account (one currency), created at registration.
func (a *Auth) ListAccounts(ctx context.Context, userID string) ([]*AccountView, error) {
	if userID == "" {
		return nil, domain.ErrUnauthenticated
	}
	u, err := a.store.ByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u.WalletID == "" {
		return nil, nil
	}
	bal, err := a.ledger.GetBalance(ctx, u.WalletID, a.walletCcyID)
	if err != nil {
		return nil, err
	}
	return []*AccountView{{
		WalletID:    u.WalletID,
		CurrencyID:  a.walletCcyID,
		TONAddress:  u.TONAddress,
		DepositMemo: u.DepositMemo,
		Available:   bal.Available,
		Held:        bal.Held,
	}}, nil
}

// DepositByMemo credits a demo deposit to the user identified by memo, via the
// ledger. Returns the owning user id and whether the credit was applied.
func (a *Auth) DepositByMemo(ctx context.Context, memo, ref, amount string, currencyID int64) (string, bool, error) {
	if memo == "" || ref == "" {
		return "", false, domain.ErrInvalidArgument
	}
	return a.ledger.CreditByMemo(ctx, memo, ref, amount, currencyID)
}
