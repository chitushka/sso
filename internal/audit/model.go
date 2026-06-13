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
