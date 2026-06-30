# Contributing to token-proxy

Thanks for your interest in improving token-proxy! This document explains how to
propose changes.

token-proxy is a **development-only** tool that injects real API credentials, so
contributions are reviewed with security in mind — please read the
[Security expectations](#security-expectations) below.

By participating, you agree to abide by our
[Code of Conduct](./CODE_OF_CONDUCT.md).

## Proposing changes

The `main` branch is protected: nobody (including the maintainer) pushes to it
directly, and all changes land through pull requests that pass CI.

External contributors do **not** have write access — that's intentional. The
flow is:

1. **Fork** the repository to your own account.
2. Create a topic branch in your fork (`git checkout -b feat/my-change`).
3. Make your change with tests, and ensure the checks below pass locally.
4. Open a pull request from your fork against `main`.

Notes for pull requests from forks:

- CI runs with a **read-only** token and **no repository secrets**, and a
  maintainer must **approve each workflow run** before it executes.
- Keep PRs focused; unrelated changes are easier to review when split up.
- Fill out the PR template (it appears automatically).

## Development setup

Requires **Go 1.25+**.

```sh
git clone https://github.com/<you>/token-proxy
cd token-proxy
go build ./cmd/token-proxy
```

Try it end to end against the example config:

```sh
cp token-proxy.example.yaml token-proxy.yaml
go run ./cmd/token-proxy ca           # creates + prints the local CA
go run ./cmd/token-proxy serve        # binds 127.0.0.1:8080 by default
```

## Checks to run before pushing

CI enforces all of these; running them locally first saves a round-trip:

```sh
gofmt -l .          # must print nothing
go vet ./...
go test -race ./...
```

- Match the style and structure of the surrounding code.
- Add or update tests for behaviour changes. Network/secret backends are behind
  the `internal/secrets.Source` interface — prefer fakes (see the existing
  tests) over hitting real services.
- Update the README and `token-proxy.example.yaml` when behaviour or config
  changes.

## Commit and PR conventions

- Write clear, imperative commit subjects (e.g. "add gsm version caching").
  Conventional-Commit-style prefixes (`feat:`, `fix:`, `docs:`, `ci:`) are
  welcome but not required.
- Explain the *why* in the body when it isn't obvious.
- Reference issues with `Closes #N` where applicable.

## Security expectations

token-proxy handles credentials, so changes must preserve its safety posture:

- **Never** commit secrets, tokens, or CA private keys. `*.pem` and
  `token-proxy.yaml` are git-ignored; keep it that way.
- Don't log secret values, full query strings, or request/response bodies.
- Don't weaken the dev-only guards (loopback-only bind unless `--allow-public`,
  selective MITM of configured hosts only).
- New secret sources should implement `internal/secrets.Source`, resolve by
  reference (never embed secrets in config), and support cheap revalidation
  where the backend allows it.

If you believe you've found a security vulnerability, please **do not open a
public issue**. Instead, report it privately via GitHub's
[security advisories](https://github.com/hyrrot/token-proxy/security/advisories/new).

## Adding a secret source (quick guide)

1. Implement `Source` (`Scheme`, `Fetch`, `Version`) in `internal/secrets/`.
2. Register it in `cmd/token-proxy/main.go` (`resolver.Register(...)`).
3. Document the reference scheme in the README and example config.
4. Add tests with a fake/mock backend.

## Releases

Releases are cut by a maintainer via the **Bump version** workflow (Actions →
*Bump version*), which tags `vMAJOR.MINOR.PATCH` and publishes binaries. You do
not need to bump versions in your PR.
