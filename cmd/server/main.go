// Command server runs the Auth service: identity (register/login by
// login/password) with a session JWT compatible with Service Constructor, plus a
// demo deposit-by-memo endpoint. It provisions each user a ledger account.
//
// It serves gRPC with an HTTP/JSON gateway in front. The gateway verifies the
// bearer JWT and injects the user id as x-user-id gRPC metadata, so downstream
// handlers (and, in the wider system, the constructor and ledger) see the same
// authenticated user.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

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

	// HTTP gateway. The metadata annotator verifies the bearer JWT (when present)
	// and injects x-user-id so authenticated handlers (Me) see the caller.
	gwMux := runtime.NewServeMux(runtime.WithMetadata(func(_ context.Context, r *http.Request) metadata.MD {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			return nil
		}
		sub, err := minter.Verify(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			return nil // unauthenticated; Me will reject
		}
		return metadata.Pairs(server.UserIDMetadataKey, sub)
	}))
	dialOpts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if err := authv1.RegisterAuthServiceHandlerFromEndpoint(ctx, gwMux, cfg.GRPCAddr, dialOpts); err != nil {
		return err
	}
	httpSrv := &http.Server{Addr: cfg.HTTPAddr, Handler: gwMux}

	serveErr := make(chan error, 2)
	go func() {
		log.Info("gRPC server listening", "addr", cfg.GRPCAddr, "ledger", cfg.LedgerAddr)
		serveErr <- grpcServer.Serve(lis)
	}()
	go func() {
		log.Info("HTTP gateway listening", "addr", cfg.HTTPAddr)
		serveErr <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
		grpcServer.GracefulStop()
		return nil
	}
}
