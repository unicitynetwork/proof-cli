import type { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';

/** The aggregator refused the certification request with a status the SDK knows. */
export class StampError extends Error {
  public constructor(public readonly status: string) {
    super(`Aggregator rejected the certification request: ${status}`);
    this.name = 'StampError';
  }
}

/**
 * The state the transaction spends was already certified, with a different
 * transaction: the slot is taken, and this transaction can never be certified.
 */
export class StateAlreadyCertifiedError extends Error {
  /**
   * @param {InclusionProof} proof Authenticated proof of the transaction that was certified instead.
   */
  public constructor(public readonly proof: InclusionProof) {
    super('The aggregator already certified a different transaction for this state.');
    this.name = 'StateAlreadyCertifiedError';
  }
}

/**
 * @param {unknown} error Thrown value.
 * @returns {string} The message of an Error, or the string form of anything else.
 */
export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
