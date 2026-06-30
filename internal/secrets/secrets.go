// Package secrets defines the pluggable secret-source abstraction and a
// caching resolver used to inject credentials with a minimal number of calls
// to the underlying (possibly billed) secret backends.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrVersionCheckUnsupported is returned by Source.Version when the source has
// no cheap way to determine the current version without fetching the payload.
var ErrVersionCheckUnsupported = errors.New("version check unsupported")

// Secret is a resolved secret payload plus version metadata used for caching.
type Secret struct {
	// Value is the secret payload.
	Value string
	// Version is an opaque identifier for the resolved version. An empty
	// string means the source could not report a version.
	Version string
	// Immutable indicates the reference can never change (for example a
	// pinned numeric version). The resolver may then cache it forever and
	// never revalidate.
	Immutable bool
}

// Source resolves secret references for exactly one URI scheme (e.g. "op").
//
// Implementations must be safe for concurrent use.
type Source interface {
	// Scheme is the reference scheme this source handles, without "://".
	Scheme() string

	// Fetch retrieves the secret payload for ref. ref is the full reference
	// including the "scheme://" prefix.
	Fetch(ctx context.Context, ref string) (Secret, error)

	// Version returns a cheap-to-obtain version identifier for ref WITHOUT
	// fetching the payload, so the resolver can avoid a billed read when the
	// cached value is still current. Implementations that cannot do this
	// cheaply must return ErrVersionCheckUnsupported.
	Version(ctx context.Context, ref string) (string, error)
}

// SchemeOf extracts the scheme from a "scheme://..." reference.
func SchemeOf(ref string) (string, error) {
	i := strings.Index(ref, "://")
	if i <= 0 {
		return "", fmt.Errorf("invalid secret reference %q: expected scheme://...", ref)
	}
	return ref[:i], nil
}
