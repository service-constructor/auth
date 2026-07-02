// Package server adapts the AuthService gRPC contract to the application service.
package server

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authv1 "github.com/nvsces/auth/gen/auth/v1"
	"github.com/nvsces/auth/internal/domain"
	"github.com/nvsces/auth/internal/service"
)

// AuthServer implements the generated AuthServiceServer.
type AuthServer struct {
	authv1.UnimplementedAuthServiceServer
	svc *service.Auth
}

// NewAuthServer wires the gRPC adapter.
func NewAuthServer(svc *service.Auth) *AuthServer {
	return &AuthServer{svc: svc}
}

func (s *AuthServer) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.AuthResponse, error) {
	tok, u, err := s.svc.Register(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, toStatus(err)
	}
	return &authv1.AuthResponse{Token: tok, User: userToProto(u)}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.AuthResponse, error) {
	tok, u, err := s.svc.Login(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, toStatus(err)
	}
	return &authv1.AuthResponse{Token: tok, User: userToProto(u)}, nil
}

func (s *AuthServer) Me(ctx context.Context, _ *authv1.MeRequest) (*authv1.User, error) {
	// The user id comes from the authenticated session, forwarded by the gateway
	// as x-user-id metadata.
	u, err := s.svc.Me(ctx, userIDFromContext(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	return userToProto(u), nil
}

func (s *AuthServer) ListAccounts(ctx context.Context, _ *authv1.ListAccountsRequest) (*authv1.ListAccountsResponse, error) {
	views, err := s.svc.ListAccounts(ctx, userIDFromContext(ctx))
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*authv1.Account, 0, len(views))
	for _, v := range views {
		out = append(out, &authv1.Account{
			WalletId:    v.WalletID,
			CurrencyId:  v.CurrencyID,
			TonAddress:  v.TONAddress,
			DepositMemo: v.DepositMemo,
			Available:   v.Available,
			Held:        v.Held,
		})
	}
	return &authv1.ListAccountsResponse{Accounts: out}, nil
}

func (s *AuthServer) ListCurrencies(ctx context.Context, _ *authv1.ListCurrenciesRequest) (*authv1.ListCurrenciesResponse, error) {
	currencies, err := s.svc.ListCurrencies(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	out := make([]*authv1.Currency, 0, len(currencies))
	for _, c := range currencies {
		out = append(out, &authv1.Currency{
			Id:       c.ID,
			Code:     c.Code,
			Name:     c.Name,
			Symbol:   c.Symbol,
			Decimals: c.Decimals,
			IsReal:   c.IsReal,
		})
	}
	return &authv1.ListCurrenciesResponse{Currencies: out}, nil
}

func (s *AuthServer) DepositByMemo(ctx context.Context, req *authv1.DepositByMemoRequest) (*authv1.DepositResponse, error) {
	userID, applied, err := s.svc.DepositByMemo(ctx, req.GetMemo(), req.GetRef(), req.GetAmount(), req.GetCurrencyId())
	if err != nil {
		return nil, toStatus(err)
	}
	return &authv1.DepositResponse{UserId: userID, Applied: applied}, nil
}

func userToProto(u *domain.User) *authv1.User {
	return &authv1.User{
		UserId:      u.ID,
		Login:       u.Login,
		TonAddress:  u.TONAddress,
		DepositMemo: u.DepositMemo,
		WalletId:    u.WalletID,
	}
}

// toStatus maps domain errors to gRPC codes.
func toStatus(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, domain.ErrLoginTaken):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, domain.ErrInvalidCreds):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, domain.ErrUserNotFound), errors.Is(err, domain.ErrMemoNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, domain.ErrInvalidArgument), errors.Is(err, domain.ErrRealCurrencyDeposit):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
