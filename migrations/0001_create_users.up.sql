-- Users registered by login/password. Identity only — the wallet and on-chain
-- deposit routing live in the ledger service. wallet_id, ton_address and
-- deposit_memo are cached here (populated from the ledger at registration) so
-- Me() can render the profile without a ledger round-trip.
CREATE TABLE IF NOT EXISTS users (
    user_id       TEXT        PRIMARY KEY,
    login         TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    wallet_id     TEXT        NOT NULL DEFAULT '',
    ton_address   TEXT        NOT NULL DEFAULT '',
    deposit_memo  TEXT        NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL
);

-- Login is the human-facing unique identity (case-insensitive).
CREATE UNIQUE INDEX IF NOT EXISTS users_login_uniq ON users (lower(login));
