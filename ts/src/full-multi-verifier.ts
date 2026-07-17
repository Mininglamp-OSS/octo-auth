/**
 * newFullMultiVerifier — convenience constructor that stitches all three
 * realms together behind a single MultiVerifier.
 *
 * See design doc §4.2 and Go SDK's full_multi_verifier.go. Recommended entry
 * point for services (like octo-fleet) that accept every credential kind.
 * cfg is shared across the three child verifiers so they use the same cache
 * / metrics / logger.
 */

import type { Config } from './config.js'
import { applyDefaults } from './config.js'
import type { MultiVerifier } from './verifier.js'
import { newMultiVerifier } from './verifier.js'
import { newSessionVerifier } from './session-verifier.js'
import { newBotTokenVerifier } from './bot-token-verifier.js'
import { newUserKeyVerifier } from './user-key-verifier.js'

export function newFullMultiVerifier(cfg: Config): MultiVerifier {
  applyDefaults(cfg)
  return newMultiVerifier(
    newSessionVerifier(cfg),
    newBotTokenVerifier(cfg),
    newUserKeyVerifier(cfg),
  )
}
