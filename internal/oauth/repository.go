package oauth

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	CreateClient(ctx context.Context, c Client) (Client, error)
	FindClientByID(ctx context.Context, id uuid.UUID) (Client, error)
	FindClientByClientID(ctx context.Context, clientID string) (Client, error)
	ListClients(ctx context.Context, limit, offset int) ([]Client, error)
	UpdateClient(ctx context.Context, c Client) (Client, error)
	DeleteClient(ctx context.Context, id uuid.UUID) error
	CreateAuthorizationCode(ctx context.Context, code AuthorizationCode) (AuthorizationCode, error)
	FindAuthorizationCodeByHash(ctx context.Context, codeHash string) (AuthorizationCode, error)
	MarkAuthorizationCodeUsed(ctx context.Context, id uuid.UUID) error
}
