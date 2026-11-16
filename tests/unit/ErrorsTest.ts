import { JsonRpcDataError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcDataError.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { JsonRpcResponseError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcResponseError.js';
import { SleepError } from '@unicitylabs/state-transition-sdk/lib/util/InclusionProofUtils.js';
import { VerificationError } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationError.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { CliError, describeError, toExitCode, usageError } from '../../src/errors.js';
import { StampError } from '../../src/lib/errors.js';
import { LineageError } from '../../src/lib/LineageClient.js';

function errno(code: string, path?: string): NodeJS.ErrnoException {
  const error: NodeJS.ErrnoException = new Error(`${code}: ${path ?? ''}`);
  error.code = code;
  error.path = path;
  return error;
}

describe('toExitCode', () => {
  const failed = new VerificationResult('Rule', VerificationStatus.FAIL, 'nope');

  it.each<[string, unknown, number]>([
    ['CliError carries its own code', new CliError('x', 7), 7],
    ['usage error', usageError('bad'), 2],
    ['aggregator rejection', new StampError('REQUEST_EXPIRED'), 3],
    ['timeout waiting for the proof', new SleepError('timeout'), 3],
    ['HTTP failure', new JsonRpcNetworkError(502, 'bad gateway'), 3],
    ['malformed JSON-RPC response', new JsonRpcResponseError('broken'), 3],
    ['JSON-RPC error object', new JsonRpcDataError({ code: -32000, message: 'denied' }), 3],
    ['fetch connection failure', new TypeError('fetch failed'), 3],
    ['token failed SDK verification', new VerificationError('bad token', failed), 1],
    ['not a valid lineage token', new LineageError('x', 'INVALID_TOKEN'), 1],
    ['lineage revision slot already taken', new LineageError('x', 'ALREADY_CERTIFIED'), 1],
    ['wrong key for the lineage', new LineageError('x', 'WRONG_KEY'), 2],
    ['finalized lineage', new LineageError('x', 'FINALIZED'), 2],
    ['file not found', errno('ENOENT', '/x'), 2],
    ['file exists', errno('EEXIST', '/x'), 2],
    ['anything else', new Error('?'), 2],
    ['a non-error value', 'oops', 2],
  ])('%s', (_name, error, code) => {
    expect(toExitCode(error)).toBe(code);
  });

  it('reports an interrupt regardless of the error', () => {
    expect(toExitCode(new SleepError('aborted'), true)).toBe(130);
  });
});

describe('describeError', () => {
  it('prints the verification tree for verification errors', () => {
    const text = describeError(
      new VerificationError('Invalid token', new VerificationResult('R', VerificationStatus.FAIL, 'why')),
    );
    expect(text).toContain('Invalid token');
    expect(text).toContain('VerificationResult[R]');
    expect(text).toContain('why');
  });

  it('explains fetch failures with their cause', () => {
    const error = new TypeError('fetch failed', { cause: new Error('ECONNREFUSED') });
    expect(describeError(error)).toEqual('Could not reach the gateway: ECONNREFUSED');
  });

  it('explains gateway HTTP failures, with a hint for rate limits and bad keys', () => {
    expect(describeError(new JsonRpcNetworkError(429, 'Too Many Requests\n'))).toEqual(
      'Gateway rate limit reached for this API key (HTTP 429: Too Many Requests). Wait before retrying; the limit is set by the subscription.',
    );
    expect(describeError(new JsonRpcNetworkError(401, ''))).toEqual(
      'Gateway refused the API key (HTTP 401). Check UNICITY_API_KEY.',
    );
    expect(describeError(new JsonRpcNetworkError(502, 'bad gateway'))).toEqual(
      'Gateway returned HTTP 502: bad gateway',
    );
  });

  it('shows the path for file system errors and explains an existing output file', () => {
    expect(describeError(errno('ENOENT', '/missing.cbor'))).toEqual('ENOENT: /missing.cbor');
    expect(describeError(errno('EEXIST', '/out.cbor'))).toEqual(
      'Refusing to overwrite /out.cbor; pass --force or another --out.',
    );
  });

  it('falls back to the message or the value', () => {
    expect(describeError(new Error('plain'))).toEqual('plain');
    expect(describeError(42)).toEqual('42');
  });
});
