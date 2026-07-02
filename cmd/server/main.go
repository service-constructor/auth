// Command server runs the Auth service: identity (register/login by
// login/password) with a session JWT compatible with Service Constructor, plus a
// demo deposit-by-memo endpoint. It provisions each user a ledger account.
//
// It is a pure gRPC service behind the standalone gateway. The gateway verifies
// the bearer JWT and injects x-user-id metadata, which authenticated handlers
// (Me, ListAccounts) read to identify the caller.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"

	authv1 "github.com/nvsces/auth/gen/auth/v1"
	"github.com/nvsces/auth/internal/config"
	"github.com/nvsces/auth/internal/ledgerclient"
	"github.com/nvsces/auth/internal/repository/postgres"
	"github.com/nvsces/auth/internal/server"
	"github.com/nvsces/auth/internal/service"
	"github.com/nvsces/auth/internal/token"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("auth exited with error", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log.Info("applying migrations")
	if err := postgres.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}

	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	ledger, err := ledgerclient.Dial(cfg.LedgerAddr)
	if err != nil {
		return err
	}
	defer ledger.Close()

	minter := token.NewMinter([]byte(cfg.JWTSecret), cfg.TokenTTL)
	repo := postgres.NewUserRepository(pool)
	svc := service.New(repo, ledger, minter, cfg.DefaultCurrencyID,
		service.WithSuperAdmins(cfg.SuperAdminLogins))
	authSrv := server.NewAuthServer(svc)

	grpcServer := grpc.NewServer()
	authv1.RegisterAuthServiceServer(grpcServer, authSrv)

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return err
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("gRPC server listening", "addr", cfg.GRPCAddr, "ledger", cfg.LedgerAddr)
		serveErr <- grpcServer.Serve(lis)
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		grpcServer.GracefulStop()
		return nil
	}
}
