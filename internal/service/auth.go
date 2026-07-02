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
// at registration and when listing a user's accounts.
type LedgerAccount struct {
	WalletID   string
	TONAddress string
	Memo       string
	CurrencyID int64
}

// Balance is a wallet's available/held for a currency, as reported by the ledger.
type Balance struct {
	Available string
	Held      string
}

// Currency is a currency from the ledger's reference catalog. IsReal tells test
// money (mock-fundable) from real money (funded only by on-chain deposits).
type Currency struct {
	ID       int64
	Code     string
	Name     string
	Symbol   string
	Decimals int32
	IsReal   bool
}

// LedgerClient is the port to the ledger service. The gRPC client adapter
// implements it; tests use a fake.
type LedgerClient interface {
	// CreateAccount provisions (or returns) a user's ledger account for a currency.
	CreateAccount(ctx context.Context, userID string, currencyID int64) (*LedgerAccount, error)
	// ListAccounts returns every account a user owns (one per currency).
	ListAccounts(ctx context.Context, userID string) ([]*LedgerAccount, error)
	// ListCurrencies returns the ledger's currency catalog (the set of active
	// currencies a user gets a wallet for at registration).
	ListCurrencies(ctx context.Context) ([]*Currency, error)
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

	// Provision a ledger account (wallet + TON deposit routing) for every active
	// currency. The default-currency account is cached on the user row for display
	// (Me, and the primary wallet_id the constructor's /pay path uses).
	currencies, err := a.ledger.ListCurrencies(ctx)
	if err != nil {
		return "", nil, err
	}
	for _, c := range currencies {
		acc, err := a.ledger.CreateAccount(ctx, u.ID, c.ID)
		if err != nil {
			return "", nil, err
		}
		if c.ID == a.walletCcyID {
			u.WalletID = acc.WalletID
			u.TONAddress = acc.TONAddress
			u.DepositMemo = acc.Memo
		}
	}
	// The default currency must exist in the catalog so the user has a primary
	// wallet; guard against a misconfigured catalog rather than storing a blank.
	if u.WalletID == "" {
		return "", nil, domain.ErrInternal
	}

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

// ListAccounts returns the user's accounts with live balances from the ledger:
// one per currency the user was provisioned a wallet for at registration.
func (a *Auth) ListAccounts(ctx context.Context, userID string) ([]*AccountView, error) {
	if userID == "" {
		return nil, domain.ErrUnauthenticated
	}
	accs, err := a.ledger.ListAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	views := make([]*AccountView, 0, len(accs))
	for _, acc := range accs {
		bal, err := a.ledger.GetBalance(ctx, acc.WalletID, acc.CurrencyID)
		if err != nil {
			return nil, err
		}
		views = append(views, &AccountView{
			WalletID:    acc.WalletID,
			CurrencyID:  acc.CurrencyID,
			TONAddress:  acc.TONAddress,
			DepositMemo: acc.Memo,
			Available:   bal.Available,
			Held:        bal.Held,
		})
	}
	return views, nil
}

// ListCurrencies returns the ledger's currency reference catalog, for the
// cabinet to label accounts and tell test money from real money.
func (a *Auth) ListCurrencies(ctx context.Context) ([]*Currency, error) {
	return a.ledger.ListCurrencies(ctx)
}

// DepositByMemo credits a demo deposit to the user identified by memo, via the
// ledger. Returns the owning user id and whether the credit was applied.
//
// It is a mock funding path, so it only credits test currencies (is_real=false).
// Real currencies (e.g. GRAM) are funded solely by the on-chain deposit watcher;
// a mock credit for one is rejected with InvalidArgument.
func (a *Auth) DepositByMemo(ctx context.Context, memo, ref, amount string, currencyID int64) (string, bool, error) {
	if memo == "" || ref == "" {
		return "", false, domain.ErrInvalidArgument
	}
	real, err := a.isRealCurrency(ctx, currencyID)
	if err != nil {
		return "", false, err
	}
	if real {
		return "", false, domain.ErrRealCurrencyDeposit
	}
	return a.ledger.CreditByMemo(ctx, memo, ref, amount, currencyID)
}

// isRealCurrency reports whether currencyID is real money, per the ledger's
// catalog. An unknown currency is rejected as an invalid argument.
func (a *Auth) isRealCurrency(ctx context.Context, currencyID int64) (bool, error) {
	currencies, err := a.ledger.ListCurrencies(ctx)
	if err != nil {
		return false, err
	}
	for _, c := range currencies {
		if c.ID == currencyID {
			return c.IsReal, nil
		}
	}
	return false, domain.ErrInvalidArgument
}
