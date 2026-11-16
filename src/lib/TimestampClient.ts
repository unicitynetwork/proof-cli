import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationStatus } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import type { ITransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/ITransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import {
  InclusionProofVerificationRule,
  InclusionProofVerificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/transaction/verification/rule/InclusionProofVerificationRule.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import { SleepError, waitInclusionProof } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';

import { TIMESTAMP_RECIPIENT, TIMESTAMP_TOKEN_TYPE } from './constants.js';
import { StampError, StateAlreadyCertifiedError } from './errors.js';
import { ITimestampNetwork } from './networks.js';
import { TimestampPayload } from './TimestampPayload.js';
import { createVerificationContext } from './verification.js';

export const DEFAULT_TIMEOUT_MS = 60_000;
export const DEFAULT_POLL_INTERVAL_MS = 1_000;

export interface ICertifyOptions {
  /**
   * Called when the aggregator already held this very transaction, submitted by an
   * earlier run: the proof returned is that run's, and nothing new was certified.
   */
  readonly onAlreadyCertified?: () => void;
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

const KNOWN_STATUSES: readonly string[] = Object.values(CertificationStatus);
const SUCCESS_STATUS: string = CertificationStatus.SUCCESS;
/**
 * The aggregator's answer when it already holds a request for the state being
 * spent. The SDK does not list it; aggregator-go sends it for every repeated
 * state id, whether the earlier request was this very transaction or another.
 */
export const STATE_ID_EXISTS_STATUS = 'STATE_ID_EXISTS';

/**
 * Look up the inclusion proof the aggregator already holds for the state that
 * `transaction` spends, and tell whether it certifies this transaction.
 *
 * A proof for another transaction is reported only once it authenticates against
 * the trust base under that other transaction's hash; the hash comparison alone
 * comes before any authentication, and a gateway could fake it.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {VerificationContext} context Verification context for the network behind the client.
 * @param {ITransaction} transaction Transaction whose state is looked up.
 * @param {AbortSignal} [signal] Abort signal for the request.
 * @returns {Promise<InclusionProof|null>} The verified proof of this transaction, or null when
 *   the state is not certified yet or the proof does not verify.
 * @throws {StateAlreadyCertifiedError} If the state was certified with another transaction.
 */
export async function findCertifiedProof(
  client: StateTransitionClient,
  context: VerificationContext,
  transaction: ITransaction,
  signal?: AbortSignal,
): Promise<InclusionProof | null> {
  const stateId = await StateId.fromTransaction(transaction);
  let proof: InclusionProof | null;
  try {
    proof = (await client.getInclusionProof(stateId, { signal })).inclusionProof;
  } catch (error) {
    if (error instanceof JsonRpcNetworkError && error.status === 404) {
      return null;
    }
    throw error;
  }
  if (proof === null) {
    return null;
  }
  const certified = proof;
  const verify = async (transactionHash: DataHash): Promise<InclusionProofVerificationStatus> =>
    (
      await InclusionProofVerificationRule.verify(
        context.trustBase,
        context.predicateVerifier,
        context.unicityCertificateVerifier,
        certified,
        transactionHash,
        transaction.expiresAt,
        transaction.lockScript,
        transaction.sourceStateHash,
      )
    ).status;

  const status = await verify(await transaction.calculateTransactionHash());
  if (status === InclusionProofVerificationStatus.OK) {
    return certified;
  }
  if (
    status === InclusionProofVerificationStatus.TRANSACTION_HASH_MISMATCH &&
    (await verify(certified.certificationData.transactionHash)) === InclusionProofVerificationStatus.OK
  ) {
    throw new StateAlreadyCertifiedError(certified);
  }
  return null;
}

/**
 * Submit a certification request and wait for its inclusion proof.
 *
 * `STATE_ID_EXISTS` means the aggregator already holds a request for this state.
 * If it is this transaction, a repeated run, the proof it holds is returned; if
 * it is another, {@link StateAlreadyCertifiedError} says so. Any other status the
 * SDK does not list is a warning rather than a failure, and the proof that then
 * arrives is checked against this transaction's hash anyway.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {VerificationContext} context Verification context for the network behind the client.
 * @param {CertificationData} certificationData Request to submit.
 * @param {ITransaction} transaction Transaction the request certifies.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<InclusionProof>} Verified inclusion proof.
 * @throws {StampError} If the aggregator returns a known failure status.
 * @throws {StateAlreadyCertifiedError} If the state was certified with another transaction.
 * @throws {SleepError} If the proof does not arrive before the timeout or abort.
 */
export async function certifyTransaction(
  client: StateTransitionClient,
  context: VerificationContext,
  certificationData: CertificationData,
  transaction: ITransaction,
  options: ICertifyOptions = {},
): Promise<InclusionProof> {
  const response = await client.submitCertificationRequest(certificationData, { signal: options.signal });
  const exists = response.status === STATE_ID_EXISTS_STATUS;
  if (exists) {
    const proof = await findCertifiedProof(client, context, transaction, options.signal);
    if (proof !== null) {
      options.onAlreadyCertified?.();
      return proof;
    }
  } else if (response.status !== SUCCESS_STATUS) {
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
  try {
    const proof = await waitInclusionProof(
      client,
      context.trustBase,
      context.predicateVerifier,
      context.unicityCertificateVerifier,
      transaction,
      AbortSignal.any(signals),
      options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS,
    );
    if (exists) {
      // The earlier request for this state was this transaction, certified in its own round.
      options.onAlreadyCertified?.();
    }
    return proof;
  } catch (error) {
    // The earlier request was still waiting for its round. The SDK reports a proof
    // of another transaction only as a plain Error, so look again to say what it is.
    if (exists && !(error instanceof SleepError)) {
      await findCertifiedProof(client, context, transaction, options.signal);
    }
    throw error;
  }
}

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
  const proof = await certifyTransaction(
    client,
    context,
    await CertificationData.fromMintTransaction(transaction),
    transaction,
    options,
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
