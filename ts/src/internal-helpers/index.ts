/**
 * internal-helpers barrel — re-exports the two service-to-service helpers.
 *
 * Subpath: `@mininglamp-oss/octo-auth/internal-helpers`
 */

export {
  NotifyClient,
  newNotifyClient,
  maskToken,
  DEFAULT_NOTIFY_TIMEOUT_MS,
  type NotifyConfig,
  type NotifyRequest,
} from './notify-client.js'

export {
  expressInternalTokenMiddleware,
  wrapNodeInternalTokenMiddleware,
  INTERNAL_TOKEN_UNAUTHORIZED_BODY,
  type InternalTokenConfig,
  type MinimalExpressRequest,
  type MinimalExpressResponse,
  type MinimalExpressNext,
  type MinimalExpressHandler,
  type MinimalNodeReq,
  type MinimalNodeRes,
  type NodeHandler,
} from './token-middleware.js'
