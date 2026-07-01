package server

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// UserIDMetadataKey is the gRPC metadata key carrying the authenticated user id.
// The HTTP gateway extracts it from the bearer JWT and injects it here; each
// service reads it and forwards it downstream, so the user context flows through
// the whole call chain (gateway → constructor → ledger).
const UserIDMetadataKey = "x-user-id"

// userIDFromContext returns the authenticated user id from incoming metadata, or
// "" if absent.
func userIDFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	vals := md.Get(UserIDMetadataKey)
	if len(vals) == 0 {
		return ""
	}
	return vals[0]
}
