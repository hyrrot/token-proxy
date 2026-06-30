# Security Policy

token-proxy is a **development-only** tool that injects real API credentials
into outgoing requests. Security is central to its purpose, so reports are very
welcome.

## Supported versions

token-proxy is pre-1.0. Security fixes are made against the **latest release**
and `main`; older tagged releases are not patched. Please reproduce on the
latest version before reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub Security Advisories:

➡️ https://github.com/hyrrot/token-proxy/security/advisories/new

Helpful details to include:

- Affected version (`token-proxy version`) and OS/arch.
- A description of the issue and its impact.
- Minimal steps or a proof of concept to reproduce.
- **Redact all real secrets, tokens, and CA private keys** from anything you
  attach.

This is a volunteer-maintained project, so responses are best-effort: expect an
acknowledgement within about a week. Once a fix is ready we'll coordinate a
release and credit you in the advisory unless you prefer to stay anonymous.

## Threat model

token-proxy is intended to run on a developer's own machine and let local tools
(or an AI agent) call authenticated APIs **without ever seeing the
credentials**. Its safety relies on a few invariants — issues that break these
are in scope:

- **Credential confidentiality.** Secret values must not leak into logs, error
  messages, query strings, or anywhere other than the intended upstream request
  header. The decrypted secret lives only in process memory and the configured
  upstream connection.
- **Loopback-by-default.** It must refuse to bind a non-loopback address unless
  `--allow-public` is explicitly passed.
- **Selective interception.** Only hosts matching a configured rule are
  TLS-terminated and injected; other CONNECT targets are tunnelled without
  decryption.
- **CA handling.** The internal CA private key is written `0600`; minted leaf
  certificates are scoped to the requested host.
- **Correct targeting.** Credentials for one rule/host must not be injected into
  requests destined for another host.

### Out of scope

These are documented user decisions, not vulnerabilities:

- Running with `--allow-public` on an untrusted network.
- Adding the internal CA to your OS/system trust store (the docs advise
  per-tool trust instead).
- Committing your own `token-proxy.yaml`, `*.pem`, or secrets to a repository.
- Compromise of the underlying secret backend (1Password, Google Secret
  Manager) or your GCP/1Password credentials.

## A reminder

token-proxy is for local development only. Do not deploy it as shared
infrastructure or expose it to networks you do not control.
