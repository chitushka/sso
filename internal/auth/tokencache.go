package auth

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AccessCacheTTL is how long BearerAuth may reuse a cached account state before
// re-reading it. Kept short so revocation (block, "sign out everywhere",
// password reset) still takes effect within this window.
const AccessCacheTTL = 5 * time.Second

// accessCacheMax bounds the number of cached entries; above it, expired ones are
// swept on write so the map cannot grow without limit.
const accessCacheMax = 10000

// TokenCacheInvalidator drops a user's cached access state. Mutations that must
// take effect immediately (block, "sign out everywhere") call it so they do not
// have to wait out the cache TTL.
type TokenCacheInvalidator interface {
	Invalidate(userID uuid.UUID)
}

// CachedTokenChecker memoizes AccessState for a short TTL so BearerAuth avoids a
// database round-trip on every authenticated request. Staleness is bounded by
// the TTL: a just-blocked account keeps access for at most that long.
type CachedTokenChecker struct {
	inner TokenChecker
	ttl   time.Duration
	mu    sync.Mutex
	cache map[uuid.UUID]accessEntry
}

type accessEntry struct {
	active        bool
	invalidBefore *time.Time
	expires       time.Time
}

func NewCachedTokenChecker(inner TokenChecker, ttl time.Duration) *CachedTokenChecker {
	return &CachedTokenChecker{inner: inner, ttl: ttl, cache: map[uuid.UUID]accessEntry{}}
}

func (c *CachedTokenChecker) AccessState(ctx context.Context, userID uuid.UUID) (bool, *time.Time, error) {
	now := time.Now()
	c.mu.Lock()
	if e, ok := c.cache[userID]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.active, e.invalidBefore, nil
	}
	c.mu.Unlock()

	// Errors (e.g. user not found) are never cached; only a definitive state is.
	active, invalidBefore, err := c.inner.AccessState(ctx, userID)
	if err != nil {
		return false, nil, err
	}
	c.mu.Lock()
	c.evictExpired(now)
	c.cache[userID] = accessEntry{active: active, invalidBefore: invalidBefore, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return active, invalidBefore, nil
}

// Invalidate drops a user's cached state so the next request re-reads it from
// the source. Called right after blocking an account or "sign out everywhere"
// so those take effect immediately instead of after the TTL.
func (c *CachedTokenChecker) Invalidate(userID uuid.UUID) {
	c.mu.Lock()
	delete(c.cache, userID)
	c.mu.Unlock()
}

func (c *CachedTokenChecker) evictExpired(now time.Time) {
	if len(c.cache) < accessCacheMax {
		return
	}
	for k, e := range c.cache {
		if now.After(e.expires) {
			delete(c.cache, k)
		}
	}
}
