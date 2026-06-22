# Changelog

Cross-SDK change log organised by contract version. Per-SDK release tags
(e.g. `sdk-go/v1.0.0`) are listed under the contract version they implement.

## contract/v1 (auth-v1)

Initial contract. Defines three endpoints:

- `POST /v1/auth/verify` — verify a user session token, return identity +
  optional context (`spaces[]`, `owned_bots_by_space{}` when
  `include=context`).
- `POST /v1/auth/verify-bot` — verify a bot token (`bf_` user-bot or
  `app_` app-bot prefix), return bot identity + owner + scope.
- `POST /v1/auth/verify-api-key` — verify a `uk_` API key, return owner
  identity + optional context.

Error codes (`errors-v1.yaml`):
`AUTH_TOKEN_MISSING` 401 / `AUTH_TOKEN_INVALID` 401 /
`AUTH_BOT_UNAVAILABLE` 503 / `AUTH_KIND_MISMATCH` 403 /
`AUTH_SPACE_FORBIDDEN` 403 / `AUTH_UPSTREAM_UNAVAILABLE` 503.

### sdk-go/v1.0.0

First release of the Go SDK.

- `auth.Client` with in-memory LRU cache keyed on SHA-256 of the token
  (never raw); configurable TTL (default 60s), max size (default 10k),
  HTTP timeout / retries.
- Gin middleware with three scopes: `ScopeWeb` (session tokens),
  `ScopeBot` (bot tokens), `ScopeDaemon` (API keys), and `ScopeAny`.
- Decorators `RequireSpaceMember()` (fail-closed when
  `X-Space-Id` is not in the verified `spaces[]`) and `RequireOwner(extractor)`.
- Context accessors: `GetLoginUID`, `GetAuthKind`, `GetSpaceID`,
  `GetRelatedUIDs`, `GetVerifiedSpaces`, `GetOwnedBotsBySpace`.
- Built-in Prometheus `Collector` implementation; `NewNoopCollector` for
  services that don't run Prom.
- Strict prefix validation: `uk_` ≥32 chars, `bf_` ≥16 chars; malformed
  tokens are rejected client-side (don't hit octo-server).
- Fail-closed on upstream 5xx (no stale-cache fallback) so revocation
  windows stay bounded by cache TTL.
