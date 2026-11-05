import { JsonRpcDataError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcDataError.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { JsonRpcResponseError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcResponseError.js';
import { SleepError } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';
import { VerificationError } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationError.js';

import { errorMessage, StampError } from './lib/errors.js';
import { LineageError } from './lib/lineage/LineageClient.js';

export const EXIT_OK = 0;
/** Verification failed, hash mismatch, or the input is not a token. */
export const EXIT_VERIFICATION_FAILED = 1;
/** Usage or configuration error. */
export const EXIT_USAGE = 2;
/** Network error, aggregator rejection, or timeout. */
export const EXIT_NETWORK = 3;
/** Interrupted by SIGINT. */
export const EXIT_INTERRUPTED = 130;

/** An error the CLI raises itself, carrying the exit code it maps to. */
export class CliError extends Error {
  public constructor(
    message: string,
    public readonly exitCode: number,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'CliError';
  }
}

export function usageError(message: string, options?: ErrorOptions): CliError {
  return new CliError(message, EXIT_USAGE, options);
}

function isErrno(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && typeof (error as NodeJS.ErrnoException).code === 'string';
}

/** Node's fetch reports connection failures as TypeError('fetch failed'). */
function isFetchFailure(error: unknown): error is TypeError {
  return error instanceof TypeError && /fetch/i.test(error.message);
}

/**
 * Map any error that escapes a command to an exit code. The mapping lives
 * here and nowhere else; the README documents the codes.
 *
 * @param {unknown} error Thrown value.
 * @param {boolean} interrupted Whether SIGINT fired during the command.
 * @returns {number} Exit code.
 */
export function toExitCode(error: unknown, interrupted = false): number {
  if (interrupted) {
    return EXIT_INTERRUPTED;
  }
  if (error instanceof CliError) {
    return error.exitCode;
  }
  if (
    error instanceof StampError ||
    error instanceof SleepError ||
    error instanceof JsonRpcNetworkError ||
    error instanceof JsonRpcResponseError ||
    error instanceof JsonRpcDataError ||
    isFetchFailure(error)
  ) {
    return EXIT_NETWORK;
  }
  if (error instanceof VerificationError) {
    return EXIT_VERIFICATION_FAILED;
  }
  if (error instanceof LineageError) {
    return error.code === 'INVALID_TOKEN' ? EXIT_VERIFICATION_FAILED : EXIT_USAGE;
  }
  return EXIT_USAGE;
}

/**
 * One-line, or for verification errors multi-line, description for stderr.
 *
 * @param {unknown} error Thrown value.
 * @returns {string} Text without a trailing newline.
 */
export function describeError(error: unknown): string {
  if (error instanceof VerificationError) {
    return `${error.message}\n${error.verificationResult.toString()}`;
  }
  if (isFetchFailure(error)) {
    const cause = error.cause instanceof Error ? `: ${error.cause.message}` : '';
    return `Could not reach the gateway${cause}`;
  }
  if (error instanceof JsonRpcNetworkError) {
    const body = error.message.trim();
    const detail = body === '' ? '' : `: ${body}`;
    if (error.status === 429) {
      return `Gateway rate limit reached for this API key (HTTP 429${detail}). Wait before retrying; the limit is set by the subscription.`;
    }
    if (error.status === 401 || error.status === 403) {
      return `Gateway refused the API key (HTTP ${error.status}${detail}). Check UNICITY_API_KEY.`;
    }
    return `Gateway returned HTTP ${error.status}${detail}`;
  }
  if (isErrno(error) && error.path) {
    if (error.code === 'EEXIST') {
      return `Refusing to overwrite ${error.path}; pass --force or another --out.`;
    }
    return `${error.code}: ${error.path}`;
  }
  return errorMessage(error);
}
