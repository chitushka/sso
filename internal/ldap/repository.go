package ldap

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, p Provider) (Provider, error)
	FindByID(ctx context.Context, id uuid.UUID) (Provider, error)
	List(ctx context.Context, limit, offset int) ([]Provider, error)
	ListEnabled(ctx context.Context) ([]Provider, error)
	Update(ctx context.Context, p Provider) (Provider, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
