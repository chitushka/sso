package auth

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type countingChecker struct {
	calls  atomic.Int64
	active bool
}

func (c *countingChecker) AccessState(_ context.Context, _ uuid.UUID) (bool, *time.Time, error) {
	c.calls.Add(1)
	return c.active, nil, nil
}

func TestCachedTokenCheckerServesFromCacheWithinTTL(t *testing.T) {
	inner := &countingChecker{active: true}
	c := NewCachedTokenChecker(inner, 50*time.Millisecond)
	id := uuid.New()

	for i := 0; i < 5; i++ {
		active, _, err := c.AccessState(context.Background(), id)
		if err != nil || !active {
			t.Fatalf("call %d: active=%v err=%v", i, active, err)
		}
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("within TTL the inner checker must be hit once, got %d", got)
	}

	// After the TTL expires the state is re-read.
	time.Sleep(60 * time.Millisecond)
	if _, _, err := c.AccessState(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("after TTL the inner checker must be hit again, got %d", got)
	}
}

func TestCachedTokenCheckerInvalidateForcesReread(t *testing.T) {
	inner := &countingChecker{active: true}
	c := NewCachedTokenChecker(inner, time.Minute)
	id := uuid.New()

	if _, _, err := c.AccessState(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	// Cached: a second read within the (long) TTL does not hit the inner checker.
	if _, _, err := c.AccessState(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("expected 1 inner call before invalidation, got %d", got)
	}
	// Invalidation (block / sign-out-everywhere) forces the next read to refresh.
	c.Invalidate(id)
	if _, _, err := c.AccessState(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if got := inner.calls.Load(); got != 2 {
		t.Fatalf("expected a re-read after Invalidate, got %d", got)
	}
}

func TestCachedTokenCheckerDoesNotCacheErrors(t *testing.T) {
	inner := &errChecker{}
	c := NewCachedTokenChecker(inner, time.Minute)
	id := uuid.New()
	for i := 0; i < 3; i++ {
		if _, _, err := c.AccessState(context.Background(), id); err == nil {
			t.Fatal("expected error to propagate")
		}
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("errors must not be cached, want 3 calls, got %d", got)
	}
}

type errChecker struct{ calls atomic.Int64 }

func (e *errChecker) AccessState(_ context.Context, _ uuid.UUID) (bool, *time.Time, error) {
	e.calls.Add(1)
	return false, nil, context.DeadlineExceeded
}
