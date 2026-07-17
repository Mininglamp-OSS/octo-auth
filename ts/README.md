# @mininglamp-oss/octo-auth

Part of the [octo-auth monorepo](../README.md); the wire contract this SDK implements lives in [`../contract/`](../contract).

Client SDK to verify [octo-server](https://github.com/Mininglamp-OSS/octo-server) credentials — human session tokens, bot tokens (`bf_`), and user API keys (`uk_`) — behind a unified `Verifier` interface, with pluggable cache and metrics.

TypeScript / pure ESM. Mirrors the [Go SDK](../go) for language parity.

## Overview

- Three verifier realms — session, bot, api-key — behind a single `Verifier` interface plus a `MultiVerifier` facade that dispatches by credential prefix.
- Pluggable `Cache` (in-mem LRU default via `lru-cache`), `MetricsCollector` (no-op default), and console-shaped `Logger`.
- Typed `OctoAuthError` values with a fail-closed default HTTP error mapper.
- Ready-made middlewares for `express` and `@hocuspocus/server`.
- Optional helpers: short-lived JWT issuance/verification (`layer2`, backed by `jose`) and shared-secret `X-*-Token` client/middleware (`internal-helpers`).

## Installation

```
npm install @mininglamp-oss/octo-auth
```

Requires Node.js **>= 20** for global `fetch` and `AbortSignal.any`.

## Quickstart

### Session verifier (human tokens)

```ts
import { newSessionVerifier } from '@mininglamp-oss/octo-auth'

const verifier = newSessionVerifier({
  baseUrl: process.env.OCTO_SERVER_URL!,
})

const principal = await verifier.verify('<session-token>')
console.log(principal.uid, principal.name, principal.role)
```

### Bot-token verifier

```ts
import { newBotTokenVerifier } from '@mininglamp-oss/octo-auth'

const verifier = newBotTokenVerifier({ baseUrl: process.env.OCTO_SERVER_URL! })
const principal = await verifier.verify('bf_...')
```

### User-API-key verifier

```ts
import { newUserKeyVerifier } from '@mininglamp-oss/octo-auth'

const verifier = newUserKeyVerifier({ baseUrl: process.env.OCTO_SERVER_URL! })
const principal = await verifier.verify('uk_...')
```

### All three behind one facade

```ts
import { newFullMultiVerifier } from '@mininglamp-oss/octo-auth'

const verifier = newFullMultiVerifier({ baseUrl: process.env.OCTO_SERVER_URL! })
// Dispatches by prefix: uk_ → api-key, bf_ / app_ → bot, else → session.
```

### With express middleware

```ts
import express from 'express'
import { newFullMultiVerifier } from '@mininglamp-oss/octo-auth'
import { expressMiddleware } from '@mininglamp-oss/octo-auth/middleware/express'

const verifier = newFullMultiVerifier({
  baseUrl: process.env.OCTO_SERVER_URL!,
})

const app = express()
app.use(expressMiddleware({ verifier, spaceHeader: 'X-Space-Id' }))

app.get('/hello', (req, res) => {
  res.json({ uid: req.principal?.uid, kind: req.principal?.kind })
})
```

### With Hocuspocus `onAuthenticate`

```ts
import { Server } from '@hocuspocus/server'
import { newSessionVerifier } from '@mininglamp-oss/octo-auth'
import { hocuspocusHook } from '@mininglamp-oss/octo-auth/middleware/hocuspocus'

const verifier = newSessionVerifier({ baseUrl: process.env.OCTO_SERVER_URL! })

const server = Server.configure({
  extensions: [hocuspocusHook({ verifier })],
})
```

## Subpath exports

- `@mininglamp-oss/octo-auth` — verifier / principal / errors / config / cache
- `@mininglamp-oss/octo-auth/middleware/express` — express middleware factory
- `@mininglamp-oss/octo-auth/middleware/hocuspocus` — hocuspocus `onAuthenticate` hook
- `@mininglamp-oss/octo-auth/internal-helpers` — `NotifyClient` + `expressInternalTokenMiddleware`
- `@mininglamp-oss/octo-auth/layer2` — short-lived JWT issue / verify (HS256)

## Peer dependencies

`express` and `@hocuspocus/server` are declared as **optional** peer dependencies — install them only when using the corresponding middleware. `jose` and `lru-cache` are regular dependencies.

## Node version

Requires Node.js **>= 20** for global `fetch` and `AbortSignal.any`.

## License

Apache-2.0 — see [LICENSE](../LICENSE) at the repository root.
