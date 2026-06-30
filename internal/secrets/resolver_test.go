package secrets

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	scheme     string
	mu         sync.Mutex
	value      string
	version    string
	immutable  bool
	versionErr error

	fetches  int
	versions int
}

func (f *fakeSource) Scheme() string { return f.scheme }

func (f *fakeSource) Fetch(ctx context.Context, ref string) (Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	return Secret{Value: f.value, Version: f.version, Immutable: f.immutable}, nil
}

func (f *fakeSource) Version(ctx context.Context, ref string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.versions++
	if f.versionErr != nil {
		return "", f.versionErr
	}
	return f.version, nil
}

func (f *fakeSource) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches, f.versions
}

func TestResolveCachesWithinTTL(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v1", version: "1"}
	r := NewResolver(time.Minute)
	r.Register(src)

	for i := 0; i < 3; i++ {
		got, err := r.Resolve(context.Background(), "t://x")
		if err != nil || got != "v1" {
			t.Fatalf("Resolve = %q, %v", got, err)
		}
	}
	if f, v := src.counts(); f != 1 || v != 0 {
		t.Fatalf("within TTL want 1 fetch / 0 version checks, got %d / %d", f, v)
	}
}

func TestResolveImmutableNeverRevalidates(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v", version: "5", immutable: true}
	r := NewResolver(time.Minute)
	r.Register(src)
	cur := time.Now()
	r.now = func() time.Time { return cur }

	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(time.Hour) // well past TTL
	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	if f, v := src.counts(); f != 1 || v != 0 {
		t.Fatalf("immutable want 1 fetch / 0 version checks, got %d / %d", f, v)
	}
}

func TestResolveRevalidatesWithoutFetchWhenVersionUnchanged(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v", version: "7"}
	r := NewResolver(time.Minute)
	r.Register(src)
	cur := time.Now()
	r.now = func() time.Time { return cur }

	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(2 * time.Minute) // expire TTL
	got, err := r.Resolve(context.Background(), "t://x")
	if err != nil || got != "v" {
		t.Fatalf("Resolve = %q, %v", got, err)
	}
	// The cheap version check should have avoided a second (billed) fetch.
	if f, v := src.counts(); f != 1 || v != 1 {
		t.Fatalf("want 1 fetch / 1 version check, got %d / %d", f, v)
	}
}

func TestResolveFetchesWhenVersionChanged(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v1", version: "1"}
	r := NewResolver(time.Minute)
	r.Register(src)
	cur := time.Now()
	r.now = func() time.Time { return cur }

	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	src.value, src.version = "v2", "2"
	src.mu.Unlock()

	cur = cur.Add(2 * time.Minute)
	got, err := r.Resolve(context.Background(), "t://x")
	if err != nil || got != "v2" {
		t.Fatalf("Resolve = %q, %v; want v2", got, err)
	}
	if f, v := src.counts(); f != 2 || v != 1 {
		t.Fatalf("want 2 fetches / 1 version check, got %d / %d", f, v)
	}
}

func TestResolveRefetchesWhenVersionUnsupported(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v", version: "", versionErr: ErrVersionCheckUnsupported}
	r := NewResolver(time.Minute)
	r.Register(src)
	cur := time.Now()
	r.now = func() time.Time { return cur }

	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(2 * time.Minute)
	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	if f, _ := src.counts(); f != 2 {
		t.Fatalf("version-unsupported source should refetch on expiry, got %d fetches", f)
	}
}

func TestSetTTLTakesEffect(t *testing.T) {
	src := &fakeSource{scheme: "t", value: "v", version: "1"}
	r := NewResolver(time.Minute)
	r.Register(src)
	cur := time.Now()
	r.now = func() time.Time { return cur }

	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	cur = cur.Add(2 * time.Minute) // beyond the original 1m TTL

	// Shrinking would force revalidation; instead grow the TTL so the entry is
	// still considered fresh and no source call happens.
	r.SetTTL(10 * time.Minute)
	if _, err := r.Resolve(context.Background(), "t://x"); err != nil {
		t.Fatal(err)
	}
	if f, v := src.counts(); f != 1 || v != 0 {
		t.Fatalf("after raising TTL want 1 fetch / 0 version checks, got %d / %d", f, v)
	}
}

func TestResolveUnknownScheme(t *testing.T) {
	r := NewResolver(time.Minute)
	if _, err := r.Resolve(context.Background(), "nope://x"); err == nil {
		t.Fatal("want error for unknown scheme")
	}
}
