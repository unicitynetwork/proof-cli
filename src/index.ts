/**
 * The library: offline verification, plus stamping through a gateway.
 *
 * Verification on its own is available from `@unicitylabs/proof-cli/verify`, whose
 * module graph cannot reach the aggregator client. Prefer that entry point in code
 * that only checks proofs — importing this one pulls in the gateway stack a
 * verifier never calls.
 *
 * Every name here is listed deliberately. A symbol added to a module under
 * `src/lib/` is internal until it appears in this file or in `src/verify.ts`.
 */

export * from './verify.js';

export { TIMESTAMP_RECIPIENT } from './lib/constants.js';
export { StampError } from './lib/errors.js';
export { resolveNetwork } from './lib/networks.js';
export type { INetworkOverrides, ITimestampNetwork } from './lib/networks.js';
export { DEFAULT_TIMEOUT_MS, stamp, stampWith } from './lib/TimestampClient.js';
export type { ICertifyOptions, IStampOptions } from './lib/TimestampClient.js';
