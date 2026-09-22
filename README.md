# octo-auth

Client SDK to verify [octo-server](https://github.com/Mininglamp-OSS/octo-server) credentials — human session tokens, User Bot tokens (`bf_`), and user API keys (`uk_`) — behind a single `Verifier` interface with pluggable cache and metrics. Ships in Go and TypeScript for parity across the octo services.

## Repository layout

| Path                | Contents                                                                      |
| ------------------- | ----------------------------------------------------------------------------- |
| [`contract/`](./contract) | OpenAPI 3.1 wire contracts for the three `/v1/auth/verify*` endpoints and the Bot `/v1/auth/resolve` endpoint. |
| [`go/`](./go)             | Go SDK. Requires Go 1.25+. Middleware for `net/http`, `gin`, `echo`, and `wkhttp`. |
| [`ts/`](./ts)             | TypeScript SDK (pure ESM). Requires Node 20+. Middleware for `express` and `@hocuspocus/server`. |

## Verifier realms

Both SDKs expose the same three realms behind a unified `Verifier` interface, plus a `MultiVerifier` facade that dispatches by credential prefix:

- **sessionVerifier** — human web-session tokens (32-hex UUID, no prefix).
- **botTokenVerifier** — User Bot tokens (`bf_<...>`). App Bot tokens (`app_<...>`) are reserved for a future release.
- **userKeyVerifier** — long-lived user API keys (`uk_<...>`).

See [`contract/auth-v1.yaml`](./contract/auth-v1.yaml) for the wire schema and [`contract/errors-v1.yaml`](./contract/errors-v1.yaml) for the error-code enumeration.

Bot identity resolution with an explicit Space and optional owner delegation is
specified in [`contract/auth-resolve.yaml`](./contract/auth-resolve.yaml). Both
SDKs keep the existing verification API unchanged and expose a separate Bot
resolver for this new contract.

## Getting started

- Go: `go get github.com/Mininglamp-OSS/octo-auth/go` — quickstart in [`go/README.md`](./go/README.md).
- TypeScript: `npm install @mininglamp-oss/octo-auth` — quickstart in [`ts/README.md`](./ts/README.md).

## License

Apache 2.0 — see [LICENSE](./LICENSE).
