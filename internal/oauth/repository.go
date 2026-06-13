package oauth

import "context"

type Repository interface {
	CreateClient(ctx context.Context, c Client) (Client, string, error)
	ListClients(ctx context.Context) ([]Client, error)
	FindClientByClientID(ctx context.Context, clientID string) (Client, error)
	CreateCode(ctx context.Context, c AuthorizationCode) (AuthorizationCode, error)
	ConsumeCode(ctx context.Context, hash string) (AuthorizationCode, error)
}
