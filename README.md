# token-proxy

A **development-only** local forwarding proxy that injects API credentials into
outgoing requests, so an AI coding agent (or any tool) can call authenticated
Web APIs **without ever seeing the credentials**.

You point your tool's `HTTPS_PROXY` at token-proxy and tell it to trust
token-proxy's internal CA. The agent makes ordinary requests
(`curl https://api.github.com/...`); token-proxy transparently adds the
`Authorization` header, pulling the secret from a pluggable secret source
(1Password or Google Secret Manager) and caching it in memory.

```
  agent ──HTTPS_PROXY──▶  token-proxy  ──▶  real API
  curl https://api.github.com/user        (CONNECT intercepted, TLS terminated
  (no token in the agent)                  with a cert valid under the local CA,
                                           Authorization: Bearer <secret> added,
                                           re-encrypted to the upstream)
```

## Why

Handing API tokens to an autonomous agent is risky: the token ends up in the
agent's context, logs, shell history, or a file it can read. The usual
workaround — have the agent print a `curl` command for you to run yourself — is
tedious and breaks the loop. token-proxy keeps the credential on your side of
the boundary: the agent can *use* the API but can never *read* the token.

## How it works

- It is an **HTTP forwarding (MITM) proxy**, like mitmproxy/Burp. Clients set
  `HTTP_PROXY`/`HTTPS_PROXY`.
- For HTTPS, the client sends `CONNECT`. If the target host **matches a rule**,
  token-proxy terminates TLS using a certificate it mints on the fly, signed by
  its **own internal CA** (which you trust on your dev machine). It injects the
  configured headers and forwards the request to the real upstream over a fresh
  TLS connection — so the upstream sees a normal authenticated call and the
  client sees a valid certificate.
- If the target host **matches no rule**, the connection is **blind-tunnelled**:
  bytes are copied through without being decrypted. token-proxy only ever
  decrypts traffic it is configured to add credentials to.
- Secrets come from a **pluggable secret source** and are **cached in memory**.

## Install / build

Requires Go 1.25+.

```sh
go build -o token-proxy ./cmd/token-proxy
```

## Quick start

1. Create a config (start from the example):

   ```sh
   cp token-proxy.example.yaml token-proxy.yaml
   $EDITOR token-proxy.yaml
   ```

2. Print the CA path and trust instructions (creates the CA on first run):

   ```sh
   ./token-proxy ca
   ```

3. Start the proxy:

   ```sh
   ./token-proxy serve --config token-proxy.yaml
   ```

4. Point a tool at it and trust the CA (development machine only):

   ```sh
   export HTTPS_PROXY=http://127.0.0.1:8080
   export HTTP_PROXY=http://127.0.0.1:8080
   export SSL_CERT_FILE="$HOME/.config/token-proxy/ca-cert.pem"   # curl, git
   # Node:   export NODE_EXTRA_CA_CERTS=$HOME/.config/token-proxy/ca-cert.pem
   # Python: export REQUESTS_CA_BUNDLE=$HOME/.config/token-proxy/ca-cert.pem

   curl https://api.github.com/user      # token injected by token-proxy
   ```

## Configuration

See [`token-proxy.example.yaml`](./token-proxy.example.yaml) for a fully
commented example. Key points:

- **Rules** map host glob patterns to headers. First match wins. A `*` matches
  exactly one DNS label (`*.github.com` matches `api.github.com`, not
  `a.b.github.com`).
- **Header values are Go templates** with these functions:
  - `secret "<ref>"` — resolve a secret reference (see below)
  - `base64 <s>`, `trim <s>`, `env "<NAME>"`
- This makes composite credentials easy, e.g. HTTP Basic:

  ```yaml
  value: 'Basic {{ printf "%s:%s" (secret "op://v/u/username") (secret "op://v/u/password") | base64 }}'
  ```

### Secret sources

Secret sources are selected by the reference scheme and are pluggable
(`internal/secrets.Source`). The first release ships two:

| Scheme | Backend | Reference form | Auth |
| --- | --- | --- | --- |
| `op://`  | 1Password CLI (`op`) | `op://<vault>/<item>/<field>` | `op` installed & signed in |
| `gsm://` | Google Secret Manager | `gsm://<project>/<secret>[/<version>]` | Application Default Credentials |

### Caching & billing minimisation

Secrets are cached in memory so token-proxy does not hit the source on every
request:

- A cached value is served for `cache.ttl` (default 5m) with no source contact.
- After the TTL, token-proxy revalidates. For Google Secret Manager a
  `gsm://.../latest` reference is checked with the cheap **`GetSecretVersion`**
  metadata call; the billed **`AccessSecretVersion`** read is only repeated when
  the underlying version number actually changed.
- A **pinned** version (`gsm://project/secret/5`) is immutable, so it is read
  **once** and cached for the lifetime of the process — never revalidated.

## Security model & limitations

token-proxy is **for local development only.**

- **Loopback by default.** It refuses to bind a non-loopback address. Exposing
  it to your network would let anyone on it make calls with your credentials.
  You must pass `--allow-public` to override — don't, unless you fully
  understand the risk.
- **It is a deliberate MITM.** Its CA can mint a certificate for any host. Trust
  the CA per-tool via env vars (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, …)
  rather than adding it to your OS/system trust store, and keep `ca-key.pem`
  private (it is written `0600`).
- **Secrets are decrypted in this process's memory** while cached. Credentials
  are never written to logs (token-proxy logs method/host/path only, never
  header values or query strings).
- It only intercepts hosts you configure; everything else is tunnelled
  untouched.

## How it compares

token-proxy overlaps with general-purpose intercepting proxies but is purpose-
built for one job: **injecting secrets the client must not see, from a real
secret manager, with a valid-looking certificate.**

| | **token-proxy** | **Burp Suite** | **Fiddler** | **mitmproxy** |
| --- | --- | --- | --- | --- |
| Primary purpose | Inject credentials so an agent can use APIs without seeing them | Web security testing | Web debugging / capture | Interactive HTTPS debugging proxy |
| Own internal CA, on-the-fly certs | ✅ | ✅ | ✅ | ✅ |
| Credential injection from a **secret manager** | ✅ Built-in (1Password, Google Secret Manager; pluggable) | ⚠️ Manual rules / custom extension | ⚠️ Custom rules (FiddlerScript) | ⚠️ Custom addon script |
| Secrets kept **out of config & logs** | ✅ Referenced by URI, resolved at runtime, never logged | ❌ Typically pasted into rules | ❌ Typically in scripts | ❌ Up to your script |
| In-memory cache w/ version-aware revalidation to cut secret-manager billing | ✅ | ❌ | ❌ | ❌ |
| Refuses non-loopback bind without an explicit flag | ✅ | ❌ | ❌ | ❌ (bind is freely configurable) |
| Selective MITM (only configured hosts decrypted, rest tunnelled) | ✅ By design | ⚙️ Configurable | ⚙️ Configurable | ⚙️ Configurable |
| Footprint | Single static Go binary, headless | Large GUI (JVM) | GUI app | Python, CLI/TUI + scriptable |
| Best for | Letting AI agents / scripts call authed APIs safely | Pentesting | Traffic inspection | General HTTPS debugging & scripting |

You *can* bend mitmproxy/Burp/Fiddler into doing credential injection with a
custom script — token-proxy's value is that this is the **only** thing it does,
safely by default: secrets come from a real manager by reference, are cached
with minimal billing, never touch logs, and it won't expose itself to your
network by accident.

## Development

```sh
go test ./...      # unit + end-to-end proxy tests
go vet ./...
```

Package layout:

- `cmd/token-proxy` — CLI (`serve`, `ca`)
- `internal/config` — config loading, host matching
- `internal/ca` — internal CA, on-the-fly leaf certificates
- `internal/secrets` — `Source` interface, caching `Resolver`, 1Password & GSM
- `internal/proxy` — the forwarding/MITM proxy and header injection

## Status

Initial release. Development-only by design.
