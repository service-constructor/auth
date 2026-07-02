// Package ledgerclient adapts the ledger gRPC API to the auth service's
// LedgerClient port. It forwards the caller's user context downstream (x-user-id)
// so the ledger sees the same user the gateway authenticated.
package ledgerclient

import (
	"context"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ledgerv1 "github.com/nvsces/ledger/gen/ledger/v1"

	"github.com/nvsces/auth/internal/service"
)

// Client wraps a ledger gRPC connection.
type Client struct {
	conn *grpc.ClientConn
	svc  ledgerv1.LedgerServiceClient
}

// Dial connects to the ledger service at addr (plaintext; the demo runs on a
// trusted network).
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, svc: ledgerv1.NewLedgerServiceClient(conn)}, nil
}

// Close releases the connection.
func (c *Client) Close() error { return c.conn.Close() }

// CreateAccount provisions the user's ledger account.
func (c *Client) CreateAccount(ctx context.Context, userID string, currencyID int64) (*service.LedgerAccount, error) {
	acc, err := c.svc.CreateAccount(ctx, &ledgerv1.CreateAccountRequest{
		UserId: userID, CurrencyId: currencyID,
	})
	if err != nil {
		return nil, err
	}
	return &service.LedgerAccount{
		WalletID:   acc.GetWalletId(),
		TONAddress: acc.GetTonAddress(),
		Memo:       acc.GetMemo(),
		CurrencyID: acc.GetCurrencyId(),
	}, nil
}

// ListAccounts returns every account the user owns (one per currency).
func (c *Client) ListAccounts(ctx context.Context, userID string) ([]*service.LedgerAccount, error) {
	resp, err := c.svc.ListAccounts(ctx, &ledgerv1.ListAccountsRequest{UserId: userID})
	if err != nil {
		return nil, err
	}
	out := make([]*service.LedgerAccount, 0, len(resp.GetAccounts()))
	for _, acc := range resp.GetAccounts() {
		out = append(out, &service.LedgerAccount{
			WalletID:   acc.GetWalletId(),
			TONAddress: acc.GetTonAddress(),
			Memo:       acc.GetMemo(),
			CurrencyID: acc.GetCurrencyId(),
		})
	}
	return out, nil
}

// ListCurrencies returns the ledger's currency catalog.
func (c *Client) ListCurrencies(ctx context.Context) ([]*service.Currency, error) {
	resp, err := c.svc.ListCurrencies(ctx, &ledgerv1.ListCurrenciesRequest{})
	if err != nil {
		return nil, err
	}
	out := make([]*service.Currency, 0, len(resp.GetCurrencies()))
	for _, cur := range resp.GetCurrencies() {
		out = append(out, &service.Currency{
			ID:       cur.GetId(),
			Code:     cur.GetCode(),
			Name:     cur.GetName(),
			Symbol:   cur.GetSymbol(),
			Decimals: cur.GetDecimals(),
			IsReal:   cur.GetIsReal(),
		})
	}
	return out, nil
}

// GetBalance returns a wallet's available/held for a currency.
func (c *Client) GetBalance(ctx context.Context, walletID string, currencyID int64) (*service.Balance, error) {
	b, err := c.svc.GetBalance(ctx, &ledgerv1.GetBalanceRequest{WalletId: walletID, CurrencyId: currencyID})
	if err != nil {
		return nil, err
	}
	return &service.Balance{Available: b.GetAvailable(), Held: b.GetHeld()}, nil
}

// CreditByMemo resolves the account by memo and posts the deposit.
func (c *Client) CreditByMemo(ctx context.Context, memo, ref, amount string, currencyID int64) (string, bool, error) {
	acc, err := c.svc.GetAccountByMemo(ctx, &ledgerv1.GetAccountByMemoRequest{Memo: memo})
	if err != nil {
		return "", false, err
	}
	if acc.GetWalletId() == "" {
		return "", false, errors.New("no wallet for memo")
	}
	resp, err := c.svc.Deposit(ctx, &ledgerv1.DepositRequest{
		Ref: ref, WalletId: acc.GetWalletId(), Amount: amount, CurrencyId: currencyID,
	})
	if err != nil {
		return "", false, err
	}
	return acc.GetUserId(), resp.GetApplied(), nil
}
