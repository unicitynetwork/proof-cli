/**
 * Offline verification: everything needed to check a proof, and nothing that can
 * reach a gateway.
 *
 * The module graph behind this entry point contains no aggregator client, no
 * JSON-RPC transport and no Node builtin, which is what makes "offline" a property
 * of the import rather than a promise in the documentation. `PublicApiTest`
 * enforces it.
 *
 * Every name here is listed deliberately. A symbol added to a module under
 * `src/lib/` is internal until it appears in this file or in `src/index.ts`.
 */

export { PAYLOAD_VERSION, TIMESTAMP_TAG, TIMESTAMP_TOKEN_TYPE, TIMESTAMP_TOKEN_TYPE_HEX } from './lib/constants.js';
export { bundledTrustBase, isNetworkName, NETWORK_NAMES, NETWORKS, networkNameForId } from './lib/networks.js';
export type { INetworkPreset, NetworkName } from './lib/networks.js';
export { TimestampIssuanceVerifier } from './lib/TimestampIssuanceVerifier.js';
export { decodePayload, TimestampPayload, TimestampPayloadError } from './lib/TimestampPayload.js';
export type { DecodedPayload } from './lib/TimestampPayload.js';
export { describeToken, verificationFailure, verify } from './lib/TimestampVerification.js';
export type {
  ITimestampDescription,
  ITimestampVerificationResult,
  ITimestampVerifyOptions,
} from './lib/TimestampVerification.js';
export { createVerificationContext } from './lib/verification.js';
