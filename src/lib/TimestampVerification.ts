import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { TIMESTAMP_RECIPIENT_ENCODED, TIMESTAMP_TOKEN_TYPE } from './constants.js';
import { decodePayload, TimestampPayload } from './TimestampPayload.js';
import { createVerificationContext } from './verification.js';

export interface ITimestampVerifyOptions {
  /** Digest the token is expected to carry. */
  readonly expectedDigest?: Uint8Array;
}

/** Everything that can be read off a token without verifying it. */
export interface ITimestampDescription {
  readonly epoch: bigint;
  readonly networkId: NetworkId;
  readonly payload: TimestampPayload | null;
  readonly payloadError: string | null;
  readonly recipientIsTimestampBurn: boolean;
  /** Unix seconds; the certified time of the stamp. */
  readonly referenceTime: bigint;
  readonly roundNumber: bigint;
  /** Unix seconds; consensus-signed upper bound of the reference time. */
  readonly roundTimestamp: bigint;
  readonly tokenId: TokenId;
  readonly tokenTypeIsTimestamp: boolean;
  readonly transferCount: number;
}

export interface ITimestampVerificationResult extends ITimestampDescription {
  /** SDK result tree, or null when verification was not reached. */
  readonly details: VerificationResult<VerificationStatus> | null;
  /** Null when no expected digest was given or the comparison was not reached. */
  readonly expectedDigestMatches: boolean | null;
  readonly reason: string | null;
  readonly status: 'FAIL' | 'OK';
}

/**
 * Read the timestamp fields off a token without verifying anything.
 *
 * @param {Token} token Any SDK token.
 * @returns {ITimestampDescription} What the token claims.
 */
export function describeToken(token: Token): ITimestampDescription {
  const genesis = token.genesis;
  const certificate = genesis.inclusionProof.unicityCertificate;
  const { error: payloadError, payload } = decodePayload(genesis.data);

  return {
    epoch: certificate.unicitySeal.epoch,
    networkId: token.networkId,
    payload,
    payloadError,
    recipientIsTimestampBurn: EncodedPredicate.equals(genesis.recipient, TIMESTAMP_RECIPIENT_ENCODED),
    referenceTime: genesis.referenceTime,
    roundNumber: certificate.inputRecord.roundNumber,
    roundTimestamp: certificate.inputRecord.timestamp,
    tokenId: token.id,
    tokenTypeIsTimestamp: areUint8ArraysEqual(token.type.bytes, TIMESTAMP_TOKEN_TYPE.bytes),
    transferCount: token.transactions.length,
  };
}

/**
 * Build a failed verification result around a token description.
 *
 * @param {ITimestampDescription} description Fields read off the token.
 * @param {string} reason Why verification failed.
 * @param {VerificationResult<VerificationStatus>|null} details SDK result tree, if verification ran.
 * @param {boolean|null} expectedDigestMatches Digest comparison outcome, if one was requested.
 * @returns {ITimestampVerificationResult} Failed result.
 */
export function verificationFailure(
  description: ITimestampDescription,
  reason: string,
  details: VerificationResult<VerificationStatus> | null = null,
  expectedDigestMatches: boolean | null = null,
): ITimestampVerificationResult {
  return { ...description, details, expectedDigestMatches, reason, status: 'FAIL' };
}

/**
 * Verify a timestamp token offline against a trust base.
 *
 * @param {Token} token Token to verify.
 * @param {RootTrustBase} trustBase Trust base of the network the token claims.
 * @param {ITimestampVerifyOptions} options Expected digest.
 * @returns {Promise<ITimestampVerificationResult>} Outcome with the SDK result tree.
 */
export async function verify(
  token: Token,
  trustBase: RootTrustBase,
  options: ITimestampVerifyOptions = {},
): Promise<ITimestampVerificationResult> {
  const description = describeToken(token);
  if (description.transferCount > 0) {
    return verificationFailure(
      description,
      `Timestamp tokens carry no transfers; this one has ${description.transferCount}.`,
    );
  }
  if (!description.tokenTypeIsTimestamp) {
    return verificationFailure(
      description,
      `Not a timestamp token: token type ${HexConverter.encode(token.type.bytes)}.`,
    );
  }

  const details = await token.verify(createVerificationContext(trustBase));
  if (details.status !== VerificationStatus.OK) {
    return verificationFailure(description, explainFailure(details, description, trustBase), details);
  }
  if (options.expectedDigest === undefined) {
    return { ...description, details, expectedDigestMatches: null, reason: null, status: 'OK' };
  }
  // Not dead code, and not a pass: reachable only if `describeToken` and the
  // issuance verifier disagree about the payload, which is exactly the case that
  // must not report OK with the caller's comparison quietly skipped.
  if (description.payload === null) {
    return verificationFailure(
      description,
      `Cannot check the expected hash: the payload could not be read (${description.payloadError ?? 'no payload'}).`,
      details,
    );
  }
  if (!areUint8ArraysEqual(description.payload.digest, options.expectedDigest)) {
    return verificationFailure(description, 'Hash mismatch: the token certifies a different digest.', details, false);
  }
  return { ...description, details, expectedDigestMatches: true, reason: null, status: 'OK' };
}

/**
 * Pick the message a user needs out of a failed verification: the deepest failing
 * rule that carries one, followed by the trust-base network when it is not the token's.
 */
function explainFailure(
  details: VerificationResult<VerificationStatus>,
  description: ITimestampDescription,
  trustBase: RootTrustBase,
): string {
  const failures = collectFailures(details);
  const explained = failures.filter((result) => result.message !== '').at(-1) ?? failures.at(-1) ?? details;
  const reason = explained.message !== '' ? explained.message : `Verification rule ${explained.rule} failed.`;
  if (description.networkId.id !== trustBase.networkId.id) {
    return `${reason} The token is for network ${description.networkId.id} and the trust base for network ${trustBase.networkId.id}; select the matching network or trust base.`;
  }
  return reason;
}

function collectFailures(result: VerificationResult<unknown>): VerificationResult<unknown>[] {
  if (result.status === VerificationStatus.OK) {
    return [];
  }
  return [result, ...result.results.flatMap((child) => collectFailures(child))];
}
