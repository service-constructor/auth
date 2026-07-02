package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nvsces/auth/internal/domain"
)

// fakeStore is an in-memory user store.
type fakeStore struct {
	byID    map[string]*domain.User
	byLogin map[string]*domain.User
}

func newFakeStore() *fakeStore {
	return &fakeStore{byID: map[string]*domain.User{}, byLogin: map[string]*domain.User{}}
}

func (s *fakeStore) Create(_ context.Context, u *domain.User) error {
	if _, ok := s.byLogin[u.Login]; ok {
		return domain.ErrLoginTaken
	}
	cp := *u
	s.byID[u.ID] = &cp
	s.byLogin[u.Login] = &cp
	return nil
}
func (s *fakeStore) ByLogin(_ context.Context, login string) (*domain.User, error) {
	u, ok := s.byLogin[login]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}
func (s *fakeStore) ByID(_ context.Context, id string) (*domain.User, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	return u, nil
}

// fakeLedger records provisioned accounts (one per user+currency) and credits by
// memo. It seeds two currencies to mirror the real catalog: DEV (test money) and
// GRAM (real money).
type fakeLedger struct {
	currencies []*Currency
	accounts   map[string]*LedgerAccount // "userID/ccy" -> account
	byUser     map[string][]*LedgerAccount
	byMemo     map[string]string // memo -> userID
	credited   map[string]string // ref -> amount (idempotency)
}

func newFakeLedger() *fakeLedger {
	return &fakeLedger{
		currencies: []*Currency{
			{ID: 1, Code: "DEV", IsReal: false},
			{ID: 2, Code: "GRAM", IsReal: true},
		},
		accounts: map[string]*LedgerAccount{},
		byUser:   map[string][]*LedgerAccount{},
		byMemo:   map[string]string{},
		credited: map[string]string{},
	}
}

func accKey(userID string, ccy int64) string {
	return userID + "/" + strconv.FormatInt(ccy, 10)
}

func (l *fakeLedger) CreateAccount(_ context.Context, userID string, ccy int64) (*LedgerAccount, error) {
	if a, ok := l.accounts[accKey(userID, ccy)]; ok {
		return a, nil
	}
	memo := "memo-" + userID + "-" + strconv.FormatInt(ccy, 10)
	a := &LedgerAccount{WalletID: "wlt-" + userID + "-" + strconv.FormatInt(ccy, 10), TONAddress: "UQ_shared", Memo: memo, CurrencyID: ccy}
	l.accounts[accKey(userID, ccy)] = a
	l.byUser[userID] = append(l.byUser[userID], a)
	l.byMemo[memo] = userID
	return a, nil
}
func (l *fakeLedger) ListAccounts(_ context.Context, userID string) ([]*LedgerAccount, error) {
	return l.byUser[userID], nil
}
func (l *fakeLedger) ListCurrencies(_ context.Context) ([]*Currency, error) {
	return l.currencies, nil
}
func (l *fakeLedger) GetBalance(_ context.Context, walletID string, _ int64) (*Balance, error) {
	return &Balance{Available: "0", Held: "0"}, nil
}
func (l *fakeLedger) CreditByMemo(_ context.Context, memo, ref, amount string, _ int64) (string, bool, error) {
	userID, ok := l.byMemo[memo]
	if !ok {
		return "", false, domain.ErrMemoNotFound
	}
	if _, done := l.credited[ref]; done {
		return userID, false, nil // replay
	}
	l.credited[ref] = amount
	return userID, true, nil
}

type fakeMinter struct{}

func (fakeMinter) Mint(userID string, roles []string, _ time.Time) (string, error) {
	return "tok-" + userID + "-" + strings.Join(roles, ","), nil
}

func newAuth() (*Auth, *fakeLedger) {
	fl := newFakeLedger()
	a := New(newFakeStore(), fl, fakeMinter{}, 1,
		WithClock(func() time.Time { return time.Unix(1000, 0).UTC() }))
	return a, fl
}

func TestRegisterProvisionsAccountAndToken(t *testing.T) {
	a, _ := newAuth()
	tok, u, err := a.Register(context.Background(), "alice", "secret1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if tok == "" || u.WalletID == "" || u.DepositMemo == "" {
		t.Fatalf("register result incomplete: tok=%q user=%+v", tok, u)
	}
	if u.TONAddress != "UQ_shared" {
		t.Errorf("ton address = %q", u.TONAddress)
	}
}

func TestRegisterRejectsShortPassword(t *testing.T) {
	a, _ := newAuth()
	if _, _, err := a.Register(context.Background(), "bob", "short"); !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestLoginRoundTrip(t *testing.T) {
	a, _ := newAuth()
	if _, _, err := a.Register(context.Background(), "carol", "secret1"); err != nil {
		t.Fatalf("Register: %v", err)
	}
	tok, u, err := a.Login(context.Background(), "carol", "secret1")
	if err != nil || tok == "" {
		t.Fatalf("Login: tok=%q err=%v", tok, err)
	}
	me, err := a.Me(context.Background(), u.ID)
	if err != nil || me.Login != "carol" {
		t.Fatalf("Me: %+v err=%v", me, err)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	a, _ := newAuth()
	_, _, _ = a.Register(context.Background(), "dave", "secret1")
	if _, _, err := a.Login(context.Background(), "dave", "wrong"); !errors.Is(err, domain.ErrInvalidCreds) {
		t.Fatalf("err = %v, want ErrInvalidCreds", err)
	}
}

func TestDepositByMemoRoutesToUserAndIsIdempotent(t *testing.T) {
	a, _ := newAuth()
	_, u, _ := a.Register(context.Background(), "erin", "secret1")

	uid, applied, err := a.DepositByMemo(context.Background(), u.DepositMemo, "tx1", "10.00", 1)
	if err != nil || !applied || uid != u.ID {
		t.Fatalf("deposit: uid=%s applied=%v err=%v", uid, applied, err)
	}
	// Replay same ref: no-op.
	_, applied, err = a.DepositByMemo(context.Background(), u.DepositMemo, "tx1", "10.00", 1)
	if err != nil || applied {
		t.Fatalf("replay: applied=%v err=%v (want false)", applied, err)
	}
}

func TestRegisterProvisionsAccountPerCurrency(t *testing.T) {
	a, fl := newAuth()
	_, u, err := a.Register(context.Background(), "grace", "secret1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// One account provisioned per catalog currency (DEV + GRAM).
	if got := len(fl.byUser[u.ID]); got != 2 {
		t.Fatalf("provisioned %d accounts, want 2", got)
	}
	// The default currency (1) account is cached on the user row.
	if u.WalletID != "wlt-"+u.ID+"-1" {
		t.Errorf("primary wallet = %q, want default-currency wallet", u.WalletID)
	}
}

func TestListAccountsReturnsAllCurrencies(t *testing.T) {
	a, _ := newAuth()
	_, u, err := a.Register(context.Background(), "heidi", "secret1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	views, err := a.ListAccounts(context.Background(), u.ID)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if len(views) != 2 {
		t.Fatalf("got %d accounts, want 2", len(views))
	}
	seen := map[int64]bool{}
	for _, v := range views {
		seen[v.CurrencyID] = true
		if v.WalletID == "" || v.Available == "" {
			t.Errorf("incomplete account view: %+v", v)
		}
	}
	if !seen[1] || !seen[2] {
		t.Errorf("missing a currency: seen=%v", seen)
	}
}

func TestDepositByMemoRejectsRealCurrency(t *testing.T) {
	a, _ := newAuth()
	_, u, _ := a.Register(context.Background(), "ivan", "secret1")
	// Currency 2 (GRAM) is real money: a mock deposit must be rejected.
	_, _, err := a.DepositByMemo(context.Background(), u.DepositMemo, "tx-real", "5.00", 2)
	if !errors.Is(err, domain.ErrRealCurrencyDeposit) {
		t.Fatalf("err = %v, want ErrRealCurrencyDeposit", err)
	}
}

func TestDepositByMemoRejectsUnknownCurrency(t *testing.T) {
	a, _ := newAuth()
	_, u, _ := a.Register(context.Background(), "judy", "secret1")
	_, _, err := a.DepositByMemo(context.Background(), u.DepositMemo, "tx-x", "5.00", 999)
	if !errors.Is(err, domain.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestTokenRolesEveryUserIsTenantAdmin(t *testing.T) {
	a, _ := newAuth()
	tok, _, err := a.Register(context.Background(), "frank", "secret1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// fakeMinter encodes roles into the token string.
	if !strings.Contains(tok, "admin") || !strings.Contains(tok, "user") {
		t.Fatalf("token roles = %q, want user+admin", tok)
	}
	if strings.Contains(tok, "super_admin") {
		t.Fatalf("non-super-admin token has super_admin: %q", tok)
	}
}

func TestTokenRolesSuperAdmin(t *testing.T) {
	fl := newFakeLedger()
	a := New(newFakeStore(), fl, fakeMinter{}, 1,
		WithClock(func() time.Time { return time.Unix(1000, 0).UTC() }),
		WithSuperAdmins([]string{"Root"})) // case-insensitive
	tok, _, err := a.Register(context.Background(), "root", "secret1")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !strings.Contains(tok, "super_admin") {
		t.Fatalf("super-admin login token missing super_admin: %q", tok)
	}
}
