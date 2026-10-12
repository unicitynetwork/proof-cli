import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { describeToken, stampWith, verify } from '../../src/lib/TimestampClient.js';
import {
  descriptionJson,
  formatIso,
  inspectText,
  keygenJson,
  keygenText,
  line,
  networkLabel,
  notATokenJson,
  notATokenText,
  resultTreeJson,
  stampJson,
  stampText,
  verifyJson,
  verifyText,
  warningLine,
} from '../../src/output.js';
import { TEST_DIGEST, TEST_DIGEST_HEX } from '../support/fixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';

// `referenceTime` is an unbounded CBOR integer, so a hostile token can carry a
// value no Date can hold. `toISOString` throws on those, which turned `inspect`
// — whose contract is to print fields without checking them — into a crash, and
// made `verify` report a bad token as a usage error.
describe('formatIso', () => {
  it('formats ordinary times', () => {
    expect(formatIso(1791549048n)).toEqual('2026-10-09T12:30:48Z');
    expect(formatIso(0n)).toEqual('1970-01-01T00:00:00Z');
  });

  it('reports an unrepresentable time instead of throwing', () => {
    for (const seconds of [10n ** 19n, -(10n ** 19n), 10n ** 30n]) {
      expect(() => formatIso(seconds)).not.toThrow();
      expect(formatIso(seconds)).toContain('out of range');
    }
  });

  it('accepts the edges of the representable range', () => {
    const maximum = 8_640_000_000_000n; // 8.64e15 ms, as seconds
    expect(formatIso(maximum)).not.toContain('out of range');
    expect(formatIso(maximum + 1n)).toContain('out of range');
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
    expect(keygenText('/k', '02ab')).toEqual('Key written    /k (mode 0600)\nPublic key     02ab');
    expect(keygenJson('/k', '02ab')).toEqual({ command: 'keygen', out: '/k', publicKey: '02ab' });
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

  describe('with a real token', () => {
    const aggregator = TestAggregatorClient.create();
    const client = new StateTransitionClient(aggregator);
    const trustBase = aggregator.rootTrustBase;

    it('renders stamp, verify and inspect views consistently', async () => {
      const token = await stampWith(client, trustBase, TEST_DIGEST, { pollIntervalMs: 10, timeoutMs: 2000 });
      const description = describeToken(token);
      const tokenIdHex = HexConverter.encode(token.id.bytes);

      const text = stampText(description, 'http://gateway.local', '/tmp/x.cbor');
      expect(text).toContain(`Stamped        SHA-256 ${TEST_DIGEST_HEX}`);
      expect(text).toContain('Network        unknown network (3) via http://gateway.local');
      expect(text).toContain('Signer         none (anonymous stamp)');
      expect(text).toContain(`Token id       ${tokenIdHex}`);
      expect(text).toContain('Written        /tmp/x.cbor');
      expect(stampText(description, 'http://gateway.local', null)).not.toContain('Written');

      const json = stampJson(description, 'http://gateway.local', '/tmp/x.cbor', token.toCBOR());
      expect(json).toMatchObject({
        command: 'stamp',
        hash: { algorithm: 'SHA-256', digest: TEST_DIGEST_HEX },
        network: { gateway: 'http://gateway.local', id: 3, name: 'unknown' },
        out: '/tmp/x.cbor',
        signer: null,
        token: HexConverter.encode(token.toCBOR()),
        tokenId: tokenIdHex,
      });
      expect(typeof json.referenceTime).toBe('string');

      const bundled = { kind: 'bundled', network: 'testnet2' } as const;
      const ok = await verify(token, trustBase, { expectedDigest: TEST_DIGEST });
      expect(verifyText(ok, bundled)).toContain(
        'Status         OK  (inclusion proof, consensus signatures and payload verified against the bundled testnet2 trust base)',
      );
      expect(verifyText(ok, bundled)).toContain('Trust base     bundled testnet2 pin');
      expect(verifyText(ok, bundled)).toContain('Expected hash  matches');
      const unchecked = await verify(token, trustBase);
      expect(verifyText(unchecked, bundled)).toContain('Expected hash  not checked; pass --file or --hash');
      expect(verifyJson(ok, bundled)).toMatchObject({
        command: 'verify',
        expectedHashMatches: true,
        reason: null,
        status: 'OK',
        trustBase: { bundledNetwork: 'testnet2', path: null, source: 'bundled' },
      });
      expect(verifyJson(ok, bundled).details?.status).toEqual('OK');

      // No trust base could be selected at all, which is how `verify` reports a
      // token whose network id matches no bundled pin.
      expect(verifyText(ok, null)).toContain('Trust base     none selected');
      expect(verifyJson(ok, null).trustBase).toBeNull();

      // An override must never be able to present itself as the bundled pin.
      const override = { kind: 'file', path: '/tmp/rogue.json' } as const;
      expect(verifyText(ok, override)).toContain('Trust base     /tmp/rogue.json  (override, not the bundled pin)');
      expect(verifyText(ok, override)).toContain('verified against /tmp/rogue.json');
      expect(verifyText(ok, override)).not.toContain('the bundled testnet2 trust base');
      expect(verifyJson(ok, override).trustBase).toEqual({
        bundledNetwork: null,
        path: '/tmp/rogue.json',
        source: 'file',
      });

      const inspected = inspectText(description);
      expect(inspected.startsWith('UNVERIFIED')).toBe(true);
      expect(inspected).toContain('Token type     timestamp');
      expect(inspected).toContain('Recipient      timestamp burn predicate');
      expect(descriptionJson(description).transferCount).toBe(0);
    });
  });
});
