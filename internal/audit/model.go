package audit

import (
	"context"
	"github.com/google/uuid"
	"time"
)

type Event struct {
	ID          uuid.UUID  `json:"id"`
	ActorUserID *uuid.UUID `json:"actor_user_id,omitempty"`
	Action      string     `json:"action"`
	TargetType  string     `json:"target_type"`
	TargetID    string     `json:"target_id"`
	IP          string     `json:"ip"`
	UserAgent   string     `json:"user_agent"`
	CreatedAt   time.Time  `json:"created_at"`
}
type Repository interface {
	Write(ctx context.Context, e Event) error
}

type Filter struct {
	ActorUserID *uuid.UUID
	Action      string
	From        *time.Time
	To          *time.Time
	Limit       int
	Offset      int
}

// Reader is separate from Repository so write-only fakes keep compiling.
type Reader interface {
	List(ctx context.Context, f Filter) ([]Event, error)
}
