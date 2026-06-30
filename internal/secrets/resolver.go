package secrets

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// Resolver caches resolved secrets and revalidates them lazily to minimise
// calls to the underlying sources. It is safe for concurrent use.
type Resolver struct {
	ttl atomic.Int64 // revalidation interval, in nanoseconds
	now func() time.Time

	mu      sync.RWMutex
	sources map[string]Source
	cache   map[string]*entry

	sf singleflight.Group
}

type entry struct {
	value     string
	version   string
	immutable bool
	checkedAt time.Time
}

// NewResolver creates a resolver whose cached entries are revalidated after
// ttl has elapsed.
func NewResolver(ttl time.Duration) *Resolver {
	r := &Resolver{
		now:     time.Now,
		sources: map[string]Source{},
		cache:   map[string]*entry{},
	}
	r.ttl.Store(int64(ttl))
	return r
}

// SetTTL updates the revalidation interval for subsequent lookups. Existing
// cache entries are kept; the new TTL is measured from their last check.
func (r *Resolver) SetTTL(ttl time.Duration) { r.ttl.Store(int64(ttl)) }

func (r *Resolver) currentTTL() time.Duration { return time.Duration(r.ttl.Load()) }

// Register adds a source. It panics if two sources share a scheme.
func (r *Resolver) Register(s Source) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sources[s.Scheme()]; dup {
		panic(fmt.Sprintf("secrets: duplicate source for scheme %q", s.Scheme()))
	}
	r.sources[s.Scheme()] = s
}

// Resolve returns the secret value for ref, using the cache where possible.
func (r *Resolver) Resolve(ctx context.Context, ref string) (string, error) {
	scheme, err := SchemeOf(ref)
	if err != nil {
		return "", err
	}

	r.mu.RLock()
	src, ok := r.sources[scheme]
	e := r.cache[ref]
	r.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("no secret source registered for scheme %q (reference %q)", scheme, ref)
	}

	// Fast path: a fresh or immutable cache entry needs no source contact.
	if e != nil && (e.immutable || r.now().Sub(e.checkedAt) < r.currentTTL()) {
		return e.value, nil
	}

	// Collapse concurrent resolutions of the same reference into one.
	v, err, _ := r.sf.Do(ref, func() (any, error) {
		return r.refresh(ctx, src, ref)
	})
	if err != nil {
		return "", err
	}
	return v.(string), nil
}

func (r *Resolver) refresh(ctx context.Context, src Source, ref string) (string, error) {
	r.mu.RLock()
	cached := r.cache[ref]
	r.mu.RUnlock()

	if cached != nil {
		if cached.immutable || r.now().Sub(cached.checkedAt) < r.currentTTL() {
			return cached.value, nil
		}
		// TTL expired: try a cheap version check before a (billed) fetch.
		if ver, err := src.Version(ctx, ref); err == nil && ver != "" && ver == cached.version {
			r.touch(ref)
			return cached.value, nil
		} else if err != nil && !errors.Is(err, ErrVersionCheckUnsupported) {
			// A real error checking the version; fall through to Fetch,
			// which will surface a meaningful error if the source is down.
		}
	}

	sec, err := src.Fetch(ctx, ref)
	if err != nil {
		return "", err
	}
	r.store(ref, sec)
	return sec.Value, nil
}

func (r *Resolver) store(ref string, sec Secret) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[ref] = &entry{
		value:     sec.Value,
		version:   sec.Version,
		immutable: sec.Immutable,
		checkedAt: r.now(),
	}
}

func (r *Resolver) touch(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.cache[ref]; e != nil {
		e.checkedAt = r.now()
	}
}

// Invalidate drops any cached value for ref, forcing the next Resolve to fetch.
func (r *Resolver) Invalidate(ref string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, ref)
}
