package users

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, u User) (User, error)
	FindByID(ctx context.Context, id uuid.UUID) (User, error)
	FindByUsername(ctx context.Context, username string) (User, error)
	FindByLDAPDN(ctx context.Context, providerID uuid.UUID, dn string) (User, error)
	List(ctx context.Context, limit, offset int) ([]User, error)
	Update(ctx context.Context, u User) (User, error)
	SetPasswordHash(ctx context.Context, id uuid.UUID, hash string) error
	SyncLDAPUser(ctx context.Context, u User) (User, error)
	TouchLastLogin(ctx context.Context, id uuid.UUID) error
	Count(ctx context.Context) (int64, error)
}
