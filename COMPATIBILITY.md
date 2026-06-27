# Compatibility Matrix

Octo-auth SDKs against octo-server `modules/auth` versions. Stage A epic:
[octo-server#428](https://github.com/Mininglamp-OSS/octo-server/issues/428).

## sdk-go

| sdk-go | requires octo-server modules/auth | behaviour |
|---|---|---|
| `sdk-go/v1.0.0` | `>= modules/auth v1.0` (Stage A epic #428 PR-A1..A4) | `verify`, `verify-bot`, `verify-api-key` all present. `verify-api-key` returns 401 until real `uk_` storage ships (stub path). |

## Contract versions

| contract | breaking change | adopters |
|---|---|---|
| `contract/v1` (auth-v1.yaml) | initial | sdk-go v1.x |

A `contract/v2` would represent a wire-breaking change (renamed field, removed
endpoint, changed semantics of an existing field). It would also necessitate
a major-version bump for every adopter SDK and a flag-day on the octo-server
side. Additive changes (new optional fields, new endpoints, new error codes)
stay on v1 and only bump SDK minor versions.

## Server-side reference

The octo-server in-tree mirror of `contract/auth-v1.yaml` lives at
`modules/auth/contract.go` in [Mininglamp-OSS/octo-server](https://github.com/Mininglamp-OSS/octo-server).
The `contract.yml` CI workflow in this repo cross-checks the two stay in sync
on every change to either side.
