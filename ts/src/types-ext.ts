/**
 * Ambient module augmentation: attach `principal` and `credential` to
 * express.Request when this package is imported alongside express.
 *
 * This is a `.ts` file (not `.d.ts`) so tsc emits both a runtime
 * `types-ext.js` (empty) AND a `.d.ts` carrying the augmentation. The empty
 * runtime file lets `import './types-ext.js'` from index.ts succeed at
 * runtime; the .d.ts carries the type-level effect to downstream consumers.
 */

import type { Principal, Credential } from './verifier.js'
import type { ResolvedPrincipal } from './resolver.js'

declare global {
  namespace Express {
    interface Request {
      principal?: Principal
      credential?: Credential
      resolvedPrincipal?: ResolvedPrincipal
    }
  }
}

export {}
