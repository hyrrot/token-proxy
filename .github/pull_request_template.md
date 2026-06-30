<!--
Thanks for contributing! Please fill out the sections below.
External contributors: open this PR from a fork — see CONTRIBUTING.md.
-->

## Summary

<!-- What does this change do, and why? -->

## Related issue

<!-- e.g. Closes #123. Delete if not applicable. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] CI / build

## How it was tested

<!-- Commands run, manual verification, new tests added, etc. -->

## Checklist

- [ ] `gofmt` clean (`gofmt -l .` prints nothing)
- [ ] `go vet ./...` passes
- [ ] `go test -race ./...` passes (added/updated tests where it makes sense)
- [ ] Docs updated (README / example config) if behaviour changed
- [ ] No secrets, tokens, or CA private keys committed
- [ ] Considered the dev-only security posture (no loopback-bind weakening,
      no logging of secret values, etc.)
