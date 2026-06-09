package audit

import (
	"context"

	"github.com/google/uuid"
)

type Event struct {
	ActorUserID  *uuid.UUID
	Action       string
	TargetType   string
	TargetID     string
	IP           string
	UserAgent    string
	MetadataJSON string
}

type Repository interface {
	Write(ctx context.Context, e Event) error
}
