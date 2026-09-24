# octo-auth Go SDK

Part of the [octo-auth monorepo](../README.md); the wire contract this SDK implements lives in [`../contract/`](../contract).

Client SDK to verify [octo-server](https://github.com/Mininglamp-OSS/octo-server) credentials — human session tokens, bot tokens (`bf_`), and user API keys (`uk_`) — behind a unified `Verifier` interface, with pluggable cache and metrics.

## Overview

- Three verifier realms — session, bot, api-key — behind a single `Verifier` interface plus a `MultiVerifier` facade that dispatches by credential prefix.
- Pluggable `Cache` (in-mem LRU default), `MetricsCollector` (no-op default), `Logger` (`slog`), and `ErrorMapperFunc`.
- Typed `*Error` values (`ErrInvalidCredential`, `ErrDisabled`, `ErrInfraFailure`, `ErrForbidden`) for `errors.Is`, plus a fail-closed default HTTP mapper.
- Ready-made middleware for `gin`, `echo`, `net/http`, and `wkhttp`.
- Optional helpers: short-lived JWT issuance/verification (`layer2`) and shared-secret `X-*-Token` client/middleware (`internal_helpers`).

## Installation

```
go get github.com/Mininglamp-OSS/octo-auth/go
```

Requires Go 1.25+.

> The toolchain floor was raised to Go 1.25 by upstream requirements from
> `github.com/gin-gonic/gin v1.12+` and `github.com/labstack/echo/v4 v4.15+`.
> Earlier Go versions cannot compile the middleware sub-packages.

## Quickstart

### Session verifier (human tokens)

```go
package main

import (
    "context"
    "log"
    "os"

    octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

func main() {
    cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
    v := octoauth.NewSessionVerifier(cfg)

    p, err := v.Verify(context.Background(), "<session-token>")
    if err != nil {
        log.Fatalf("verify: %v", err)
    }
    log.Printf("uid=%s name=%s role=%s", p.UID, p.Name, p.Role)
}
```

### Bot-token verifier

```go
cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
v := octoauth.NewBotTokenVerifier(cfg)
p, err := v.Verify(ctx, "bf_...")
```

### Bot identity and owner delegation (new Resolve API)

The Resolver uses the same Bot token as the existing Bot-token verifier; it
does not require a separate service token. A backend must derive `Action` from
its own controlled route, never accept an arbitrary Action or Human subject
from the Bot. Both modes require the request's target Space. The
`/v1/internal/` namespace identifies a backend integration API; it does not add
a caller credential or enforce network isolation. Configure `BaseURL` for the
same octo-server deployment used by the existing verifiers.

```go
cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
resolver := octoauth.NewResolver(cfg)
principal, err := resolver.Resolve(ctx, "bf_...", octoauth.ResolveRequest{
    Mode: octoauth.ModeOBO, SpaceID: "space-1", Action: "project.read",
})
if err != nil { /* deny the request; do not fall back to AS_BOT */ }
// principal.Actor is the Bot; principal.Subject is its current Human owner.
// The business service still checks Subject's current resource permissions.
```

For a Bot-self request, use `ModeAsBot` and omit `Action`. Existing `Verify`
methods and their response semantics are unchanged. See
[`../contract/auth-resolve.yaml`](../contract/auth-resolve.yaml).
For `net/http` routes, `nethttp.WrapBotResolve` fixes the mode/Action at route
registration, checks the `obo=true` marker on OBO routes, and attaches the
result for `nethttp.BotResolvedPrincipal(r.Context())`. AS_BOT routes reject
the marker, and both modes reject `on_behalf_of`, `human_uid`, and
`subject_uid`. Other HTTP frameworks should apply the same fixed-route policy
before calling the Resolver directly.
The default `space_id` query extractor is only transport plumbing: before
business access, bind or compare that Space with the Space that owns the
requested resource. Prefer a trusted `BotResolveOptions.SpaceID` extractor
when the route already knows the resource's Space.

### User-API-key verifier

```go
cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
v := octoauth.NewUserKeyVerifier(cfg)
p, err := v.Verify(ctx, "uk_...")
```

### All three behind one facade

```go
cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
mv := octoauth.NewFullMultiVerifier(cfg)
// The MultiVerifier dispatches by prefix: uk_ → api-key, bf_ / app_ → bot,
// anything else → session. Register any subset with NewMultiVerifier.
p, err := mv.Verify(ctx, credential)
```

### With gin middleware

```go
import (
    ginmw "github.com/Mininglamp-OSS/octo-auth/go/middleware/gin"
)

func main() {
    cfg := &octoauth.Config{BaseURL: os.Getenv("OCTO_SERVER_URL")}
    verifier := octoauth.NewFullMultiVerifier(cfg)

    engine := gin.New()
    engine.Use(ginmw.New(ginmw.Options{
        Verifier:    verifier,
        SpaceHeader: "X-Space-Id",
    }))
    engine.GET("/hello", func(c *gin.Context) {
        p := ginmw.Principal(c)
        c.JSON(200, gin.H{"uid": p.UID, "kind": p.Kind})
    })
    engine.Run(":8080")
}
```

The `echo`, `nethttp`, and `wkhttp` middlewares expose the same `Options` shape.

## Configuring tri-state booleans

`Config.RequestIncludeContext` and `Config.HashCacheKey` are `*bool` so the
SDK can distinguish "not set → use default" from an explicit `false`. Use the
`octoauth.Ptr` generic helper to build them:

```go
cfg := &octoauth.Config{
    BaseURL: os.Getenv("OCTO_SERVER_URL"),

    // Both default to true. Pass Ptr(false) to opt out explicitly.
    RequestIncludeContext: octoauth.Ptr(false), // skip ?include=context
    HashCacheKey:          octoauth.Ptr(false), // cache raw tokens (debug only)
}
```

Leaving a field as its zero value (nil) is equivalent to `Ptr(true)` — the
constructor `applyDefaults` step fills it in.

## API

| Symbol | Purpose |
|---|---|
| `octoauth.Config` | Shared configuration (`BaseURL`, `HTTPClient`, `Cache`, `Metrics`, `Logger`, TTLs, `RequestIncludeContext`, `HashCacheKey`). |
| `octoauth.NewResolver` / `ResolveRequest` / `ResolvedPrincipal` | Two-mode Bot identity resolution (`AS_BOT` or `OBO`); OBO returns Actor, Subject and Delegation, not business authorization. |
| `octoauth.NewSessionVerifier` / `NewBotTokenVerifier` / `NewUserKeyVerifier` | Per-realm constructors returning a `Verifier`. |
| `octoauth.NewMultiVerifier` / `NewFullMultiVerifier` | Prefix-dispatch facade over child verifiers. |
| `octoauth.Verifier` | `Kind() PrincipalKind`; `Verify(ctx, credential) (*Principal, error)`. |
| `octoauth.Principal` / `PrincipalContext` / `ContextKind` | Resolved identity plus optional `include=context` payload. |
| `octoauth.ExtractCredential` | Pulls a token from `Authorization: Bearer` with `token`-header fallback. |
| `octoauth.ValidateAPIKey` / `ValidateBotToken` | Local prefix/length checks. |
| `octoauth.Error`, `ErrKind*`, `ErrInvalidCredential`/`ErrDisabled`/`ErrInfraFailure`/`ErrForbidden` | Typed error surface for `errors.Is`. |
| `octoauth.DefaultErrorMapper` | Fail-closed status/body mapper used by every middleware unless overridden. |
| `octoauth.Cache` / `NewLRUCache` | Pluggable cache backend + in-mem LRU default (`hashicorp/golang-lru/v2`). |
| `octoauth.MetricsCollector` / `NoopMetrics` | Pluggable metrics sink. |
| `.../middleware/{gin,echo,nethttp,wkhttp}` | HTTP framework adapters. |
| `.../internal_helpers.NewNotifyClient` / `InternalTokenMiddleware` | Shared-secret producer + consumer helpers. |
| `.../layer2.IssueShortLivedToken` / `VerifyShortLivedToken` | Short-lived JWT issue + verify. |

## Local checks

```
go mod tidy
go vet ./...
gofmt -l .
go test -race ./...
```

## License

Apache-2.0 — see [LICENSE](../LICENSE) at the repository root.
