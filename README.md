# octo-auth

Unified authentication contract & SDKs for the Octo ecosystem.

[![sdk-go CI](https://github.com/Mininglamp-OSS/octo-auth/actions/workflows/sdk-go.yml/badge.svg)](https://github.com/Mininglamp-OSS/octo-auth/actions/workflows/sdk-go.yml)
[![contract](https://github.com/Mininglamp-OSS/octo-auth/actions/workflows/contract.yml/badge.svg)](https://github.com/Mininglamp-OSS/octo-auth/actions/workflows/contract.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## What this is

octo-auth is the **single source of truth** for how downstream Octo services
(octo-matter, octo-fleet, future modules) authenticate user / bot / api-key
tokens against [octo-server](https://github.com/Mininglamp-OSS/octo-server).
It ships:

- A versioned **contract** — `contract/auth-v1.yaml` (OpenAPI 3.1) — defining
  the three `/v1/auth/verify*` endpoints octo-server exposes (`modules/auth`
  internal package mirrors this contract 1:1).
- Per-language **SDKs** consuming that contract:
  - `sdk-go/` — Go SDK (v1.0.0, first release)
  - `sdk-ts/` — TypeScript SDK *(planned)*
  - `sdk-py/` — Python SDK *(planned)*

Each SDK provides:

- A typed `Client` that wraps the verify HTTP endpoints with an in-memory LRU
  cache keyed on SHA-256 of the token (never the raw token).
- An HTTP middleware (gin / express / starlette equivalent) that injects
  authenticated identity into the request context.
- `RequireScope(...)` / `RequireSpaceMember()` / `RequireOwner(...)` decorators
  that downstream services use to fail-closed cross-space access.
- A `Collector` interface for observability with built-in Prometheus
  implementation (Go) and a no-op fallback for services that don't run Prom.

## Why this exists

Before octo-auth, each downstream service hand-rolled its own verify client,
cache, middleware, and error mapping. That produced three pathologies:

- **Contract drift**: octo-fleet was calling a `/v1/auth/verify-api-key`
  endpoint octo-server didn't actually implement.
- **Implementation drift**: octo-matter used raw-string token cache keys
  (heap-dump leak risk); octo-fleet had a drop-all eviction policy
  (cache-thrash under load).
- **Evolution lock-in**: every new field on the verify response required
  synchronized edits in three external repositories.

octo-auth turns those into one contract + one SDK per language.

## Layout

```
octo-auth/
├── contract/             # OpenAPI 3.1 — single source of truth for all SDKs
│   ├── auth-v1.yaml
│   ├── errors-v1.yaml    # error code enum
│   └── examples/         # request/response samples driving contract tests
├── sdk-go/               # ★ v1 first release
│   ├── auth/             # Client, Cache, Middleware, Scope, Context, Errors
│   ├── contract/         # DTOs generated from auth-v1.yaml
│   ├── metrics/          # Prometheus + Noop Collector implementations
│   └── examples/{matter,fleet}/
├── sdk-ts/               # placeholder
├── sdk-py/               # placeholder
├── CHANGELOG.md          # cross-SDK change log, organised by contract version
├── COMPATIBILITY.md      # SDK version ↔ octo-server modules/auth version matrix
└── .github/workflows/    # per-SDK CI + contract diff check
```

## Status

- `contract/auth-v1.yaml`: **v1**, stable; backed by octo-server
  [#428](https://github.com/Mininglamp-OSS/octo-server/issues/428).
- `sdk-go/`: **v1.0.0** (first release).
- `sdk-ts/`, `sdk-py/`: not yet started — accepting contributions.

## Getting started (Go)

```go
import (
    "github.com/Mininglamp-OSS/octo-auth/sdk-go/auth"
)

func main() {
    client, err := auth.New(auth.Options{
        ServerURL: "https://octo-server.example.com",
    })
    if err != nil { panic(err) }

    r := gin.Default()
    // Mount middleware on routes that need a valid user/bot/apikey
    r.Use(client.Middleware(auth.ScopeAny))
    r.GET("/v1/things", func(c *gin.Context) {
        uid := auth.GetLoginUID(c)
        kind := auth.GetAuthKind(c)
        // ...
    })
}
```

See `sdk-go/examples/{matter,fleet}/main.go` for full integration snippets.

## Versioning

Each SDK and the contract are tagged independently:

- `sdk-go/v1.0.0`, `sdk-go/v1.1.0`...
- `sdk-ts/v1.0.0`, `sdk-py/v1.0.0` (future)
- `contract/v2.0.0` for a breaking contract revision (drives major SDK bumps)

See [COMPATIBILITY.md](COMPATIBILITY.md) for the SDK ↔ octo-server matrix.

## Contributing

- Contract changes start at `contract/auth-v1.yaml`. The
  `.github/workflows/contract.yml` runs `spectral` lint + OpenAPI diff and
  fails on breaking changes without a major version bump.
- Per-SDK changes follow standard PR flow; each SDK has its own
  `.github/workflows/sdk-*.yml`.
- See [CHANGELOG.md](CHANGELOG.md) for the cross-SDK change log; entries are
  organised by contract version, not SDK version, so cross-language
  behavioural changes stay paired.

## License

Apache 2.0 — see [LICENSE](LICENSE).
