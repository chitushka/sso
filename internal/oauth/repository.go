package oauth

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	CreateClient(ctx context.Context, c Client) (Client, string, error)
	ListClients(ctx context.Context) ([]Client, error)
	FindClientByClientID(ctx context.Context, clientID string) (Client, error)
	FindClientByID(ctx context.Context, id uuid.UUID) (Client, error)
	UpdateClient(ctx context.Context, c Client) (Client, error)
	DeleteClient(ctx context.Context, id uuid.UUID) error
	CreateCode(ctx context.Context, c AuthorizationCode) (AuthorizationCode, error)
	ConsumeCode(ctx context.Context, hash string) (AuthorizationCode, error)
	CreateRefreshToken(ctx context.Context, t RefreshToken) (RefreshToken, error)
	FindRefreshTokenByHash(ctx context.Context, hash string) (RefreshToken, error)
	MarkRefreshTokenRotated(ctx context.Context, id uuid.UUID) error
	RevokeRefreshFamily(ctx context.Context, familyID uuid.UUID) error
	RevokeRefreshTokensByUser(ctx context.Context, userID uuid.UUID) error
	GetConsent(ctx context.Context, userID uuid.UUID, clientID string) (UserConsent, error)
	SaveConsent(ctx context.Context, c UserConsent) error
}
