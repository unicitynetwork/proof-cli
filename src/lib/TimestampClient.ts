import { AggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/AggregatorClient.js';
import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationStatus } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import { waitInclusionProof } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';

import { TIMESTAMP_RECIPIENT, TIMESTAMP_TOKEN_TYPE } from './constants.js';
import { StampError } from './errors.js';
import { ITimestampNetwork } from './networks.js';
import { TimestampPayload } from './TimestampPayload.js';
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
