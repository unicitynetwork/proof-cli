import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import {
  formatIso,
  line,
  networkLabel,
  notATokenJson,
  notATokenText,
  resultTreeJson,
  toIso,
  warningLine,
} from '../../src/output.js';

describe('formatIso', () => {
  it('reports an unrepresentable time instead of throwing', () => {
    for (const seconds of [10n ** 19n, -(10n ** 19n), 10n ** 30n]) {
      expect(formatIso(seconds)).toContain('out of range');
    }
  });

  it('accepts the edges of the representable range', () => {
    const largestDateSeconds = 8_640_000_000_000n;
    expect(formatIso(largestDateSeconds)).not.toContain('out of range');
    expect(formatIso(largestDateSeconds + 1n)).toContain('out of range');
    expect(toIso(largestDateSeconds + 1n)).toBeNull();
  });
});

describe('output', () => {
  it('formats Unix seconds as ISO 8601 without milliseconds', () => {
    expect(formatIso(1791200527n)).toEqual('2026-10-05T11:42:07Z');
    expect(formatIso(0n)).toEqual('1970-01-01T00:00:00Z');
  });

  it('labels networks by id', () => {
    expect(networkLabel(1)).toEqual('mainnet (1)');
    expect(networkLabel(4)).toEqual('testnet2 (4)');
    expect(networkLabel(9)).toEqual('unknown network (9)');
  });

  it('aligns labels and renders the small envelopes', () => {
    expect(line('Status', 'OK')).toEqual('Status         OK');
    expect(notATokenText('not a token (x)')).toEqual('Status         FAIL: not a token (x)');
    expect(notATokenJson('inspect', 'bad')).toEqual({ command: 'inspect', reason: 'bad', status: 'FAIL' });
    expect(warningLine('careful')).toEqual('warning: careful\n');
  });

  it('flattens a verification result tree to plain data', () => {
    const tree = new VerificationResult('Parent', VerificationStatus.FAIL, 'outer', [
      new VerificationResult('Child', VerificationStatus.FAIL, 'inner'),
    ]);
    expect(resultTreeJson(tree)).toEqual({
      message: 'outer',
      results: [{ message: 'inner', results: [], rule: 'Child', status: 'FAIL' }],
      rule: 'Parent',
      status: 'FAIL',
    });
  });
});
