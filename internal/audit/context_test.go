package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
)

type recordingRepository struct {
	event Event
	err   error
}

func (r *recordingRepository) Write(_ context.Context, event Event) error {
	r.event = event
	return r.err
}

func TestWriteEnrichesEventFromRequestContext(t *testing.T) {
	actorUserID := uuid.New()
	repo := &recordingRepository{}
	ctx := WithRequestContext(context.Background(), actorUserID, "192.0.2.10", "audit-test")

	if err := Write(ctx, repo, Event{Action: "role_created"}); err != nil {
		t.Fatalf("write event: %v", err)
	}

	if repo.event.ActorUserID == nil || *repo.event.ActorUserID != actorUserID {
		t.Fatalf("unexpected actor: %v", repo.event.ActorUserID)
	}
	if repo.event.IP != "192.0.2.10" {
		t.Fatalf("unexpected ip: %q", repo.event.IP)
	}
	if repo.event.UserAgent != "audit-test" {
		t.Fatalf("unexpected user agent: %q", repo.event.UserAgent)
	}
}

func TestWritePreservesExplicitMetadataAndReturnsRepositoryError(t *testing.T) {
	requestActor := uuid.New()
	explicitActor := uuid.New()
	wantErr := errors.New("audit unavailable")
	repo := &recordingRepository{err: wantErr}
	ctx := WithRequestContext(context.Background(), requestActor, "192.0.2.10", "request-agent")

	err := Write(ctx, repo, Event{
		ActorUserID: &explicitActor,
		IP:          "198.51.100.20",
		UserAgent:   "explicit-agent",
	})

	if !errors.Is(err, wantErr) {
		t.Fatalf("expected repository error, got %v", err)
	}
	if repo.event.ActorUserID == nil || *repo.event.ActorUserID != explicitActor || repo.event.IP != "198.51.100.20" || repo.event.UserAgent != "explicit-agent" {
		t.Fatalf("explicit metadata was overwritten: %+v", repo.event)
	}
}
