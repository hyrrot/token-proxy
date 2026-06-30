package secrets

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// OnePassword resolves "op://vault/item/field" references using the 1Password
// CLI (`op`). The CLI must be installed and authenticated (e.g. via the
// 1Password desktop app integration or `op signin`).
//
// 1Password has no per-read billing and the CLI exposes no cheap version
// probe, so this source relies on the resolver's TTL for refresh.
type OnePassword struct {
	// Bin is the op executable; defaults to "op".
	Bin string
}

// NewOnePassword returns a 1Password source using the `op` CLI on PATH.
func NewOnePassword() *OnePassword { return &OnePassword{Bin: "op"} }

func (s *OnePassword) Scheme() string { return "op" }

func (s *OnePassword) bin() string {
	if s.Bin == "" {
		return "op"
	}
	return s.Bin
}

func (s *OnePassword) Fetch(ctx context.Context, ref string) (Secret, error) {
	if _, err := exec.LookPath(s.bin()); err != nil {
		return Secret{}, fmt.Errorf("1Password CLI %q not found on PATH: %w", s.bin(), err)
	}
	// `op read` accepts a full op:// reference and prints just the field value.
	cmd := exec.CommandContext(ctx, s.bin(), "read", "--no-newline", ref)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return Secret{}, fmt.Errorf("op read %s: %s", ref, msg)
	}
	return Secret{Value: stdout.String()}, nil
}

func (s *OnePassword) Version(ctx context.Context, ref string) (string, error) {
	return "", ErrVersionCheckUnsupported
}
