# octo-auth/sdk-go

Go SDK for [octo-auth](../) — the Octo ecosystem's unified authentication
contract.

```go
import "github.com/Mininglamp-OSS/octo-auth/sdk-go/auth"
```

## Install

```bash
go get github.com/Mininglamp-OSS/octo-auth/sdk-go@latest
```

Requires Go 1.24+.

## Quick start

```go
client, err := auth.New(auth.Options{
    ServerURL: "https://octo-server.example.com",
})
if err != nil { log.Fatal(err) }

r := gin.Default()
r.Use(client.Middleware(auth.ScopeAny))
r.GET("/v1/things", func(c *gin.Context) {
    uid := auth.GetLoginUID(c)
    kind := auth.GetAuthKind(c)
    // ...
})
```

See [`examples/matter/main.go`](examples/matter/main.go) and
[`examples/fleet/main.go`](examples/fleet/main.go) for end-to-end snippets
mirroring the integration shapes for octo-matter and octo-fleet
respectively.

## Configuration

`Options` fields (all optional except `ServerURL`):

| field         | default                  | notes                                                    |
|---------------|--------------------------|----------------------------------------------------------|
| `ServerURL`   | (required)               | octo-server base URL                                     |
| `HTTPTimeout` | 5s                       | bounds one verify call                                   |
| `MaxRetries`  | 2                        | idempotent 5xx retry budget; 100ms fixed backoff         |
| `CacheTTL`    | 60s                      | revocation-window upper bound                            |
| `CacheSize`   | 10000                    | LRU capacity                                             |
| `HTTPClient`  | `http.Client`+`Timeout`  | inject for custom transports / test round-trippers       |
| `Logger`      | `slog.Default()`         | SDK reports warn/error here                              |
| `Collector`   | Noop                     | use `metrics.NewPrometheusCollector(...)` to enable Prom |

## Middleware scopes

- `auth.ScopeAny` — accept any token kind
- `auth.ScopeWeb` — user session only
- `auth.ScopeBot` — bot token only (`bf_` or `app_`)
- `auth.ScopeDaemon` — API key only (`uk_`)

Mismatches produce **403** `AUTH_KIND_MISMATCH`.

## Decorators

- `client.RequireSpaceMember()` — fail-closed when `X-Space-Id` is not in
  the verified `spaces[]` (only when the verify response included
  context; otherwise log + pass for backward compatibility).
- `client.RequireOwner(extractor)` — 403s unless the verified principal
  matches the extracted UID.

## Context accessors

After the middleware runs, downstream handlers read identity via:

- `auth.GetLoginUID(c)` — principal UID
- `auth.GetName(c)` — display name
- `auth.GetRole(c)` — system role (sessions only)
- `auth.GetAuthKind(c)` — token kind enum
- `auth.GetSpaceID(c)` — X-Space-Id (or bot binding)
- `auth.GetRelatedUIDs(c)` — `[self, owned bots]` or `[self, owner]`
- `auth.GetVerifiedSpaces(c)` — authorised spaces list (when context_included)
- `auth.GetOwnedBotsBySpace(c)` — owned bot UIDs per space
- `auth.GetBotKind(c)` / `auth.GetOwnerUID(c)` / `auth.GetAppBotScope(c)`

## Security invariants

The SDK is built around four security invariants enforced by tests:

1. **Cache keys are SHA-256(kind+":"+token)**, never the raw token —
   a heap dump cannot leak tokens.
2. **5xx upstream responses are never cached** — caching a transient
   outage would extend the failure window beyond TTL.
3. **`RequireSpaceMember()` fails closed** when context is available.
4. **Prom label cardinality is bounded** to known enumerations
   (kind/result/reason/status_bucket); never user-supplied strings.

## Metrics

Built-in Prometheus collector exposes:

| metric                              | type      | labels                  |
|-------------------------------------|-----------|-------------------------|
| `octoauth_verify_total`             | counter   | kind, result            |
| `octoauth_verify_duration_seconds`  | histogram | kind                    |
| `octoauth_cache_hits_total`         | counter   | kind                    |
| `octoauth_cache_size`               | gauge     | -                       |
| `octoauth_cache_evicts_total`       | counter   | reason                  |
| `octoauth_upstream_errors_total`    | counter   | kind, status_bucket     |
| `octoauth_space_unverified_total`   | counter   | -                       |

```go
import (
  "github.com/prometheus/client_golang/prometheus"
  "github.com/Mininglamp-OSS/octo-auth/sdk-go/metrics"
)

client, _ := auth.New(auth.Options{
  ServerURL: "...",
  Collector: metrics.NewPrometheusCollector(prometheus.DefaultRegisterer),
})
```

Use `metrics.NewNoopCollector()` to disable metrics entirely.

## License

Apache 2.0 — inherited from the parent repo.
