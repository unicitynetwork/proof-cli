import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';

import { runVerify } from '../../src/commands/verify.js';
import { EXIT_OK, EXIT_USAGE, EXIT_VERIFICATION_FAILED } from '../../src/errors.js';
import { stampWith } from '../../src/lib/TimestampClient.js';
import { verify } from '../../src/lib/TimestampVerification.js';
import { verifyJson, verifyText } from '../../src/output.js';
import { testContext } from '../support/context.js';
import { OTHER_DIGEST_HEX, tempDir, TEST_DIGEST, TEST_DIGEST_HEX, TEST_PUBLIC_KEY_HEX } from '../support/fixtures.js';
import {
  createLineageFixture,
  ILineageFixture,
  SEAL_DIGEST_HEX,
  THIRD_DIGEST_HEX,
} from '../support/LineageFixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';
import { createTimestampToken } from '../support/TimestampFixtures.js';

// The in-memory aggregator's network id matches no bundled pin, which is the
// token `verify` cannot place and has to report before any trust base exists.
describe('runVerify on a token whose network has no bundled pin', () => {
  let file: string;

  beforeAll(async () => {
    const aggregator = TestAggregatorClient.create();
    const token = await stampWith(new StateTransitionClient(aggregator), aggregator.rootTrustBase, TEST_DIGEST, {
      pollIntervalMs: 10,
      timeoutMs: 2_000,
    });
    file = path.join(await tempDir('proof-cli-verify-'), 'token.cbor');
    await writeFile(file, token.toCBOR());
  });

  it('reports the unknown network without claiming a digest was checked', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(file, {}, sink.context)).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      expectedHashMatches: null,
      reason: 'unknown network id 3; pass --trust-base',
      status: 'FAIL',
      trustBase: null,
    });
  });

  it('refuses a contradictory command line first, as a usage error', async () => {
    await expect(
      runVerify(file, { file: 'document.pdf', hash: TEST_DIGEST_HEX }, testContext({ json: true }).context),
    ).rejects.toMatchObject({ exitCode: EXIT_USAGE, message: 'Pass either --hash or --file, not both.' });
  });
});

describe('runVerify on a document lineage', () => {
  let fixture: ILineageFixture;

  beforeAll(async () => {
    fixture = await createLineageFixture();
  });

  it('verifies a finalized lineage and says so', async () => {
    const sink = testContext();
    expect(
      await runVerify(fixture.sealedFile, { hash: SEAL_DIGEST_HEX, trustBase: fixture.trustBaseFile }, sink.context),
    ).toBe(EXIT_OK);
    const out = sink.stdout();
    expect(out).toContain('Next producer  none; the lineage is finalized (sealed and burned)\n');
    expect(out).toContain(
      `Revision 3     SHA-256 ${SEAL_DIGEST_HEX}  (final)\n  Signed by    ${fixture.bobPublicHex}\n`,
    );
    expect(out).toContain('  Passes to    nobody; sealed and burned\n');
    expect(out).toContain('Expected hash  matches revision 3 (the final)');

    const json = testContext({ json: true });
    expect(await runVerify(fixture.sealedFile, { trustBase: fixture.trustBaseFile }, json.context)).toBe(EXIT_OK);
    expect(json.json()).toMatchObject({ finalized: true, nextProducer: null, status: 'OK' });
    expect((json.json() as { revisions: { sealed: boolean }[] }).revisions.map((entry) => entry.sealed)).toEqual([
      false,
      false,
      false,
      true,
    ]);
  });

  it('verifies the lineage and lists every revision', async () => {
    const sink = testContext();
    expect(await runVerify(fixture.tokenFile, { trustBase: fixture.trustBaseFile }, sink.context)).toBe(EXIT_OK);
    const out = sink.stdout();
    expect(out).toMatch(
      /^Status {9}OK {2}\(inclusion proofs, consensus signatures, issuer signature and revision chain/,
    );
    expect(out).toContain('Token type     document lineage\n');
    expect(out).toContain(`Issuer         ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain('Revisions      3\n');
    expect(out).toContain(`Next producer  ${fixture.bobPublicHex}\n`);
    expect(out).toContain(`Revision 0     SHA-256 ${TEST_DIGEST_HEX}\n  Signed by    ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain(`Revision 1     SHA-256 ${OTHER_DIGEST_HEX}\n  Signed by    ${fixture.bobPublicHex}\n`);
    expect(out).toContain(`Revision 2     SHA-256 ${THIRD_DIGEST_HEX}\n  Signed by    ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain(`  Passes to    ${fixture.bobPublicHex}\n  Certified at`);
    expect(out).toContain('Expected hash  not checked; pass --file or --hash');
  });

  it('finds an expected hash among the revisions', async () => {
    const latest = testContext();
    await runVerify(fixture.tokenFile, { hash: THIRD_DIGEST_HEX, trustBase: fixture.trustBaseFile }, latest.context);
    expect(latest.stdout()).toContain('Expected hash  matches revision 2 (the latest)\n');

    const older = testContext({ json: true });
    expect(
      await runVerify(fixture.tokenFile, { hash: OTHER_DIGEST_HEX, trustBase: fixture.trustBaseFile }, older.context),
    ).toBe(EXIT_OK);
    expect(older.json()).toMatchObject({
      command: 'verify',
      expectedHashMatches: true,
      matchingRevisions: [1],
      status: 'OK',
      tokenType: 'lineage',
    });

    const text = testContext();
    await runVerify(fixture.tokenFile, { hash: OTHER_DIGEST_HEX, trustBase: fixture.trustBaseFile }, text.context);
    expect(text.stdout()).toContain('Expected hash  matches revision 1; superseded by revision 2\n');
  });

  it('fails on a hash no revision carries', async () => {
    const sink = testContext({ json: true });
    expect(
      await runVerify(fixture.tokenFile, { hash: 'ef'.repeat(32), trustBase: fixture.trustBaseFile }, sink.context),
    ).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      expectedHashMatches: false,
      matchingRevisions: [],
      reason: 'Hash mismatch: no revision of the lineage certifies this digest.',
      status: 'FAIL',
    });
  });

  it('fails against the wrong trust base', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(fixture.tokenFile, { network: 'testnet2' }, sink.context)).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      matchingRevisions: null,
      reason: 'The token is for network 3 and the trust base for network 4.',
      status: 'FAIL',
      trustBase: { bundledNetwork: 'testnet2', source: 'bundled' },
    });
  });

  it('reports a network it cannot place as a lineage failure', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(fixture.tokenFile, {}, sink.context)).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      reason: 'unknown network id 3; pass --trust-base',
      status: 'FAIL',
      tokenType: 'lineage',
      trustBase: null,
    });
  });
});

describe('verify output for a timestamp', () => {
  const aggregator = TestAggregatorClient.create();
  const trustBase = aggregator.rootTrustBase;
  const bundled = { kind: 'bundled', network: 'testnet2' } as const;

  it('reports the verdict, the trust base and the expected hash', async () => {
    const token = await createTimestampToken(aggregator, TEST_DIGEST);
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
  });
});
