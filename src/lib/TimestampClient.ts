import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationStatus } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { waitInclusionProof } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { TIMESTAMP_RECIPIENT, TIMESTAMP_RECIPIENT_ENCODED, TIMESTAMP_TOKEN_TYPE } from './constants.js';
import { StampError } from './errors.js';
import { ITimestampNetwork } from './networks.js';
import { decodePayload, TimestampPayload } from './TimestampPayload.js';
import { createVerificationContext } from './verification.js';

export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_POLL_INTERVAL_MS = 1_000;

export interface ICertifyOptions {
  /** Called for conditions that do not stop the stamp, such as an unknown aggregator status. */
  readonly onWarning?: (message: string) => void;
  /** Delay between inclusion-proof polls. Default {@link DEFAULT_POLL_INTERVAL_MS}. */
  readonly pollIntervalMs?: number;
  /** Caller's abort signal, combined with the timeout. */
  readonly signal?: AbortSignal;
  /** Maximum wait for the inclusion proof. Default {@link DEFAULT_TIMEOUT_MS}. */
  readonly timeoutMs?: number;
}

export interface IStampOptions extends ICertifyOptions {
  /** Permit sending the API key to a plain-HTTP gateway. Local development only. */
  readonly allowInsecureTransport?: boolean;
  /** Omit for an anonymous stamp. */
  readonly signer?: SigningService;
}

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

const KNOWN_STATUSES: readonly string[] = Object.values(CertificationStatus);
const SUCCESS_STATUS: string = CertificationStatus.SUCCESS;

/**
 * Submit a mint transaction and wait for its inclusion proof.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {VerificationContext} context Verification context for the network behind the client.
 * @param {MintTransaction} transaction Transaction to certify.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<CertifiedMintTransaction>} The transaction with its verified inclusion proof.
 * @throws {StampError} If the aggregator returns a known failure status.
 * @throws {SleepError} If the proof does not arrive before the timeout or abort.
 */
export async function certifyMintTransaction(
  client: StateTransitionClient,
  context: VerificationContext,
  transaction: MintTransaction,
  options: ICertifyOptions = {},
): Promise<CertifiedMintTransaction> {
  const response = await client.submitCertificationRequest(await CertificationData.fromMintTransaction(transaction), {
    signal: options.signal,
  });
  if (response.status !== SUCCESS_STATUS) {
    if (KNOWN_STATUSES.includes(response.status)) {
      throw new StampError(response.status);
    }
    options.onWarning?.(
      `Aggregator returned unknown status '${response.status}'; waiting for the inclusion proof anyway.`,
    );
  }

  const signals = [AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS)];
  if (options.signal) {
    signals.push(options.signal);
  }
  const proof = await waitInclusionProof(
    client,
    context.trustBase,
    context.predicateVerifier,
    context.unicityCertificateVerifier,
    transaction,
    AbortSignal.any(signals),
    options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
  );

  return transaction.toCertifiedTransaction(
    context.trustBase,
    context.predicateVerifier,
    context.unicityCertificateVerifier,
    proof,
  );
}

/**
 * Stamp a digest: mint a timestamp token through the given gateway and return it verified.
 *
 * @param {Uint8Array} digest 32-byte SHA-256 digest.
 * @param {ITimestampNetwork} network Gateway and trust base.
 * @param {string|null} apiKey Gateway API key.
 * @param {IStampOptions} options Signer, timeout, abort signal.
 * @returns {Promise<Token>} Verified timestamp token.
 */
export function stamp(
  digest: Uint8Array,
  network: ITimestampNetwork,
  apiKey: string | null,
  options: IStampOptions = {},
): Promise<Token> {
  const client = new StateTransitionClient(
    new AggregatorClient(network.gatewayUrl, apiKey, options.allowInsecureTransport ?? false),
  );
  return stampWith(client, network.trustBase, digest, options);
}

/**
 * Same as {@link stamp}, against an already constructed client, so callers can
 * supply their own aggregator client implementation.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Uint8Array} digest 32-byte SHA-256 digest.
 * @param {IStampOptions} options Signer, timeout, abort signal.
 * @returns {Promise<Token>} Verified timestamp token.
 */
export async function stampWith(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  digest: Uint8Array,
  options: IStampOptions = {},
): Promise<Token> {
  const payload = options.signer
    ? await TimestampPayload.sign(digest, options.signer)
    : TimestampPayload.anonymous(digest);
  const transaction = await MintTransaction.create(trustBase.networkId, TIMESTAMP_RECIPIENT, {
    data: payload.toCBOR(),
    tokenType: TIMESTAMP_TOKEN_TYPE,
  });
  const context = createVerificationContext(trustBase);
  return Token.mint(await certifyMintTransaction(client, context, transaction, options), context);
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
