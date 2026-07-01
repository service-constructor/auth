package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nvsces/auth/internal/domain"
)

// UserRepository persists users.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository wraps a pgx pool.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

const userColumns = `user_id, login, password_hash, wallet_id, ton_address, deposit_memo, created_at`

// Create inserts a new user. Returns domain.ErrLoginTaken if the login exists.
func (r *UserRepository) Create(ctx context.Context, u *domain.User) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO users (`+userColumns+`)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		u.ID, u.Login, u.PasswordHash, u.WalletID, u.TONAddress, u.DepositMemo, u.CreatedAt)
	if isUniqueViolation(err) {
		return domain.ErrLoginTaken
	}
	if err != nil {
		return fmt.Errorf("insert user: %w", err)
	}
	return nil
}

// ByLogin loads a user by login (case-insensitive).
func (r *UserRepository) ByLogin(ctx context.Context, login string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(login) = lower($1)`, login)
	return scanUser(row)
}

// ByID loads a user by id.
func (r *UserRepository) ByID(ctx context.Context, id string) (*domain.User, error) {
	row := r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE user_id = $1`, id)
	return scanUser(row)
}

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Login, &u.PasswordHash, &u.WalletID, &u.TONAddress, &u.DepositMemo, &u.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("scan user: %w", err)
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
