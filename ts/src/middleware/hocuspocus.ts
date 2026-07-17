/**
 * Hocuspocus onAuthenticate hook.
 *
 * See design doc §8.3. Two modes:
 *   - layer2 set   → verify JWT locally + epoch check (hot-path fast)
 *   - layer2 unset → call verifier.verify (round-trip to octo-server)
 *
 * We deliberately do not import from `@hocuspocus/server` so this file
 * compiles without the peer. The returned object shape matches Hocuspocus's
 * `Extension` interface — callers add it to `new Server({ extensions: [...] })`.
 */

import { OctoAuthError } from '../errors.js'
import type { Verifier } from '../verifier.js'
import { verifyShortLivedToken, AlgHS256 } from '../layer2.js'
import type { SigAlg } from '../layer2.js'

/**
 * Layer2Config: when set, hocuspocusHook verifies short-lived JWTs locally
 * and skips round-tripping to octo-server on every WS connection.
 */
export interface Layer2Config {
  /** HS256 secret key bytes (>= 32 bytes). */
  sigKey: Uint8Array
  /**
   * getPermissionEpoch is called during authentication; the token's
   * permission_epoch claim MUST be >= the current epoch or auth is rejected.
   * Lets the app propagate revocations within the token's remaining TTL.
   */
  getPermissionEpoch: (documentName: string) => Promise<number> | number
  /** Signature algorithm. Defaults to HS256. */
  sigAlg?: SigAlg
}

/** HocuspocusHookOptions matches design doc §8.3. */
export interface HocuspocusHookOptions {
  /** Required when layer2 is unset. */
  verifier?: Verifier
  layer2?: Layer2Config
}

/**
 * OnAuthenticatePayload is the minimum subset of Hocuspocus's
 * `onAuthenticatePayload` we consume. The real interface has more fields
 * (`connection`, `context`, etc.) — omitted here for peer-independence.
 */
export interface OnAuthenticatePayload {
  token: string
  documentName: string
}

/** OnAuthenticatedUser is what our hook returns; assignable to Hocuspocus's context user. */
export interface OnAuthenticatedUser {
  uid: string
  role?: string
}

export interface HocuspocusHook {
  onAuthenticate(
    data: OnAuthenticatePayload,
  ): Promise<{ user: OnAuthenticatedUser }>
}

/**
 * hocuspocusHook returns an object with `onAuthenticate` suitable to spread
 * into a Hocuspocus `Extension`.
 *
 * Throws synchronously if neither verifier nor layer2 is set.
 */
export function hocuspocusHook(opts: HocuspocusHookOptions): HocuspocusHook {
  if (!opts || (!opts.verifier && !opts.layer2)) {
    throw new Error(
      'octoauth/middleware/hocuspocus: either options.verifier or options.layer2 is required',
    )
  }
  return {
    async onAuthenticate(data: OnAuthenticatePayload) {
      if (!data || typeof data.token !== 'string' || data.token === '') {
        throw new OctoAuthError('invalid-credential', 'missing token')
      }
      if (opts.layer2) {
        const claims = await verifyShortLivedToken(data.token, {
          sigKey: opts.layer2.sigKey,
          sigAlg: opts.layer2.sigAlg ?? AlgHS256,
        })
        // Enforce document binding: reject when the token's document_name
        // claim does not match the target document. Empty document_name in
        // the claim is treated as invalid — an unbound token cannot be
        // relied on for a document-scoped decision. Prevents cross-document
        // authorization bypass (token minted for doc A replayed on doc B).
        if (!claims.documentName) {
          throw new OctoAuthError(
            'invalid-credential',
            'layer2: token missing document_name claim',
          )
        }
        if (claims.documentName !== data.documentName) {
          throw new OctoAuthError(
            'forbidden',
            'layer2: token document_name does not match target document',
          )
        }
        const currentEpoch = await opts.layer2.getPermissionEpoch(
          data.documentName,
        )
        if (claims.permissionEpoch < currentEpoch) {
          throw new OctoAuthError(
            'invalid-credential',
            'layer2: stale token (permission_epoch below current)',
          )
        }
        const user: OnAuthenticatedUser = { uid: claims.uid }
        if (claims.role) user.role = claims.role
        return { user }
      }
      // Non-layer2 path: verifier is guaranteed by the constructor check.
      const p = await opts.verifier!.verify(data.token)
      const user: OnAuthenticatedUser = { uid: p.uid }
      if (p.role) user.role = p.role
      return { user }
    },
  }
}
