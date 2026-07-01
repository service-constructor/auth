# Auth

Identity service for the Service Constructor demo: **register/login by
login+password**, issues a **session JWT compatible with the constructor**
(`sub=userId`, HS256, shared `AUTH_JWT_SECRET`), and provisions each user a
wallet in the [ledger](../ledger) service at registration.

It owns **only users**. The wallet and its on-chain deposit routing (TON address
+ per-user memo tag) live in the ledger — auth calls `ledger.CreateAccount` on
register and caches the returned `wallet_id`/`ton_address`/`memo` for display.

## Roles

Every token carries `roles: ["user", "admin"]`. `admin` lets a user manage **their
own** services in the [admin console](../constructor/admin-ui) (the constructor
scopes the registry by owner = `sub`), so the admin console uses the **same
login/password** as the personal cabinet. Logins listed in `SUPER_ADMIN_LOGINS`
(comma-separated, case-insensitive) additionally get `super_admin`, which sees
**every** account's services — root access, granted manually.

## Endpoints (HTTP gateway in front of gRPC)

| Method & path              | Auth        | Purpose                                  |
|----------------------------|-------------|------------------------------------------|
| `POST /v1/auth/register`   | none        | Create user, provision ledger wallet, return token |
| `POST /v1/auth/login`      | none        | Authenticate, return a fresh token       |
| `GET  /v1/auth/me`         | bearer JWT  | Return the caller's profile              |
| `POST /v1/auth/deposits`   | none (demo) | Credit a deposit to the user by memo tag |

## User context flow

The HTTP gateway verifies the bearer JWT and injects the user id as **`x-user-id`
gRPC metadata**. Handlers read it from the context (never trusting a body field),
and services forward it downstream — so the same authenticated user flows through
the whole chain: `gateway → constructor → ledger`.

## TON deposits (demo)

At registration the ledger assigns every user the **same** on-chain address
(`TON_ADDRESS`) but a **unique memo tag**. An incoming transfer is matched to a
user by its memo. `POST /v1/auth/deposits` is the demo stand-in for an on-chain
watcher: given `{memo, ref, amount}` it resolves the account in the ledger and
credits it (idempotent on `ref` — the tx hash).

## Run

```bash
# needs Postgres (`auth` DB) and the ledger service running.
AUTH_JWT_SECRET=devsecret \
DATABASE_URL="postgres://sc:sc@localhost:5432/auth?sslmode=disable" \
GRPC_ADDR=":9200" HTTP_ADDR=":8090" LEDGER_ADDR="localhost:9110" make run
```

Config (env): `DATABASE_URL`, `GRPC_ADDR` (`:9200`), `HTTP_ADDR` (`:8090`),
`AUTH_JWT_SECRET` (must match constructor), `LEDGER_ADDR` (`localhost:9110`).

## Test

```bash
make test   # service tests run with fakes (no DB needed)
```

## Layout

```
proto/auth/v1/auth.proto      gRPC + HTTP contract
gen/                          generated stubs (buf generate)
internal/domain/              user type + errors
internal/repository/postgres/ users table
internal/token/               HS256 session JWT mint/verify
internal/service/             register/login/me/deposit logic
internal/ledgerclient/        gRPC client adapter to the ledger
internal/server/              gRPC adapter + x-user-id metadata
cmd/server/                   entrypoint (gRPC + gateway)
migrations/                   embedded SQL (applied at startup)
```
