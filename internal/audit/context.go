package audit

import (
	"context"

	"github.com/google/uuid"
)

type requestContextKey struct{}

type RequestContext struct {
	ActorUserID uuid.UUID
	IP          string
	UserAgent   string
}

// WithRequestContext records the authenticated actor and request metadata so
// application services can create complete audit events without HTTP types.
func WithRequestContext(ctx context.Context, actorUserID uuid.UUID, ip, userAgent string) context.Context {
	return context.WithValue(ctx, requestContextKey{}, RequestContext{
		ActorUserID: actorUserID,
		IP:          ip,
		UserAgent:   userAgent,
	})
}

// Write enriches missing fields from the request context before persisting.
func Write(ctx context.Context, repo Repository, event Event) error {
	request, _ := ctx.Value(requestContextKey{}).(RequestContext)
	if event.ActorUserID == nil && request.ActorUserID != uuid.Nil {
		actorUserID := request.ActorUserID
		event.ActorUserID = &actorUserID
	}
	if event.IP == "" {
		event.IP = request.IP
	}
	if event.UserAgent == "" {
		event.UserAgent = request.UserAgent
	}
	return repo.Write(ctx, event)
}
