import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { runInspect } from '../../src/commands/inspect.js';
import { runVerify } from '../../src/commands/verify.js';
import { EXIT_OK, EXIT_VERIFICATION_FAILED } from '../../src/errors.js';
import { appendRevision, createLineage } from '../../src/lib/lineage/LineageClient.js';
import { testContext } from '../support/context.js';
import {
  OTHER_DIGEST,
  OTHER_DIGEST_HEX,
  tempDir,
  TEST_DIGEST,
  TEST_DIGEST_HEX,
  TEST_PRIVATE_KEY,
  TEST_PUBLIC_KEY_HEX,
} from '../support/fixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';

const THIRD_DIGEST_HEX = 'ab'.repeat(32);

describe('verify and inspect on a document lineage', () => {
  const aggregator = TestAggregatorClient.create();
  const client = new StateTransitionClient(aggregator);
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };
  const bob = SigningService.generatePrivateKey();
  const bobPublicHex = HexConverter.encode(new SigningService(bob).publicKey);
  let directory: string;
  let tokenFile: string;
  let trustBaseFile: string;
  let token: Token;

  beforeAll(async () => {
    directory = await tempDir('proof-cli-lineage-');
    // Revision 0 by the issuer naming bob, then revision 1 by bob naming the issuer, then 2 by the issuer naming bob.
    const genesis = await createLineage(
      client,
      aggregator.rootTrustBase,
      TEST_DIGEST,
      TEST_PRIVATE_KEY,
      new SigningService(bob).publicKey,
      fast,
    );
    const first = await appendRevision(
      client,
      aggregator.rootTrustBase,
      genesis,
      OTHER_DIGEST,
      bob,
      HexConverter.decode(TEST_PUBLIC_KEY_HEX),
      fast,
    );
    token = await appendRevision(
      client,
      aggregator.rootTrustBase,
      first,
      HexConverter.decode(THIRD_DIGEST_HEX),
      TEST_PRIVATE_KEY,
      new SigningService(bob).publicKey,
      fast,
    );
    tokenFile = path.join(directory, 'doc.lineage');
    await writeFile(tokenFile, token.toCBOR());
    trustBaseFile = path.join(directory, 'trust-base.json');
    await writeFile(trustBaseFile, JSON.stringify(aggregator.rootTrustBase.toJSON()));
  });

  it('verifies a finalized lineage and says so', async () => {
    const sealed = await appendRevision(
      client,
      aggregator.rootTrustBase,
      token,
      HexConverter.decode('cd'.repeat(32)),
      bob,
      null,
      fast,
    );
    const sealedFile = path.join(directory, 'sealed.lineage');
    await writeFile(sealedFile, sealed.toCBOR());

    const sink = testContext();
    expect(await runVerify(sealedFile, { hash: 'cd'.repeat(32), trustBase: trustBaseFile }, sink.context)).toBe(
      EXIT_OK,
    );
    const out = sink.stdout();
    expect(out).toContain('Next producer  none; the lineage is finalized (sealed and burned)\n');
    expect(out).toContain(`Revision 3     SHA-256 ${'cd'.repeat(32)}  (final)\n  Signed by    ${bobPublicHex}\n`);
    expect(out).toContain('  Passes to    nobody; sealed and burned\n');
    expect(out).toContain('Expected hash  matches revision 3 (the final)');

    const json = testContext({ json: true });
    expect(await runVerify(sealedFile, { trustBase: trustBaseFile }, json.context)).toBe(EXIT_OK);
    expect(json.json()).toMatchObject({ finalized: true, nextProducer: null, status: 'OK' });
    expect((json.json() as { revisions: { sealed: boolean }[] }).revisions.map((entry) => entry.sealed)).toEqual([
      false,
      false,
      false,
      true,
    ]);

    const inspected = testContext({ json: true });
    expect(await runInspect(sealedFile, inspected.context)).toBe(EXIT_OK);
    expect(inspected.json()).toMatchObject({ finalized: true, verified: false });
  });

  it('verifies the lineage and lists every revision', async () => {
    const sink = testContext();
    expect(await runVerify(tokenFile, { trustBase: trustBaseFile }, sink.context)).toBe(EXIT_OK);
    const out = sink.stdout();
    expect(out).toMatch(
      /^Status {9}OK {2}\(inclusion proofs, consensus signatures, issuer signature and revision chain/,
    );
    expect(out).toContain('Token type     document lineage\n');
    expect(out).toContain(`Issuer         ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain('Revisions      3\n');
    expect(out).toContain(`Next producer  ${bobPublicHex}\n`);
    expect(out).toContain(`Revision 0     SHA-256 ${TEST_DIGEST_HEX}\n  Signed by    ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain(`Revision 1     SHA-256 ${OTHER_DIGEST_HEX}\n  Signed by    ${bobPublicHex}\n`);
    expect(out).toContain(`Revision 2     SHA-256 ${THIRD_DIGEST_HEX}\n  Signed by    ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(out).toContain(`  Passes to    ${bobPublicHex}\n  Certified at`);
    expect(out).toContain('Expected hash  not checked; pass --file or --hash');
  });

  it('finds an expected hash among the revisions', async () => {
    const latest = testContext();
    await runVerify(tokenFile, { hash: THIRD_DIGEST_HEX, trustBase: trustBaseFile }, latest.context);
    expect(latest.stdout()).toContain('Expected hash  matches revision 2 (the latest)\n');

    const older = testContext({ json: true });
    expect(await runVerify(tokenFile, { hash: OTHER_DIGEST_HEX, trustBase: trustBaseFile }, older.context)).toBe(
      EXIT_OK,
    );
    expect(older.json()).toMatchObject({
      command: 'verify',
      expectedHashMatches: true,
      matchingRevisions: [1],
      status: 'OK',
      tokenType: 'lineage',
    });

    const text = testContext();
    await runVerify(tokenFile, { hash: OTHER_DIGEST_HEX, trustBase: trustBaseFile }, text.context);
    expect(text.stdout()).toContain('Expected hash  matches revision 1; superseded by revision 2\n');
  });

  it('fails on a hash no revision carries', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(tokenFile, { hash: 'cd'.repeat(32), trustBase: trustBaseFile }, sink.context)).toBe(
      EXIT_VERIFICATION_FAILED,
    );
    expect(sink.json()).toMatchObject({
      expectedHashMatches: false,
      matchingRevisions: [],
      reason: 'Hash mismatch: no revision of the lineage certifies this digest.',
      status: 'FAIL',
    });
  });

  it('fails against the wrong trust base', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(tokenFile, { network: 'testnet2' }, sink.context)).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      matchingRevisions: null,
      reason: 'The token is for network 3 and the trust base for network 4.',
      status: 'FAIL',
      trustBase: { bundledNetwork: 'testnet2', source: 'bundled' },
    });
  });

  it('reports a network it cannot place as a lineage failure', async () => {
    const sink = testContext({ json: true });
    expect(await runVerify(tokenFile, {}, sink.context)).toBe(EXIT_VERIFICATION_FAILED);
    expect(sink.json()).toMatchObject({
      reason: 'unknown network id 3; pass --trust-base',
      status: 'FAIL',
      tokenType: 'lineage',
      trustBase: null,
    });
  });

  it('inspects the lineage without verifying it', async () => {
    const text = testContext();
    expect(await runInspect(tokenFile, text.context)).toBe(EXIT_OK);
    expect(text.stdout()).toMatch(/^UNVERIFIED {5}/);
    expect(text.stdout()).toContain('Revisions      3\n');

    const json = testContext({ json: true });
    expect(await runInspect(tokenFile, json.context)).toBe(EXIT_OK);
    const output = json.json() as { revisions: { index: string; signer: string }[] };
    expect(output).toMatchObject({
      command: 'inspect',
      issuer: TEST_PUBLIC_KEY_HEX,
      network: { id: 3 },
      nextProducer: bobPublicHex,
      tokenId: HexConverter.encode(token.id.bytes),
      tokenType: 'lineage',
      verified: false,
    });
    expect(output.revisions.map((revision) => [revision.index, revision.signer])).toEqual([
      ['0', TEST_PUBLIC_KEY_HEX],
      ['1', bobPublicHex],
      ['2', TEST_PUBLIC_KEY_HEX],
    ]);
  });
});
