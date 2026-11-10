import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { runVerify } from '../../src/commands/verify.js';
import { EXIT_OK, EXIT_USAGE, EXIT_VERIFICATION_FAILED } from '../../src/errors.js';
import { describeLineage, ILineageVerificationResult } from '../../src/lib/LineageVerification.js';
import { stampWith } from '../../src/lib/TimestampClient.js';
import { verify } from '../../src/lib/TimestampVerification.js';
import { lineageVerifyJson, lineageVerifyText, verifyJson, verifyText } from '../../src/output.js';
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

  it('refuses --token-id on a token that is not a lineage, as a usage error', async () => {
    await expect(
      runVerify(file, { tokenId: 'ab'.repeat(32) }, testContext({ json: true }).context),
    ).rejects.toMatchObject({
      exitCode: EXIT_USAGE,
      message: '--token-id applies to document lineage tokens only; this token is not one.',
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
    expect(out).toContain('Lineage id     not checked; pass --token-id to tie this to the lineage you were given\n');
  });

  it('checks the lineage against the token id it was given', async () => {
    const tokenId = HexConverter.encode(fixture.token.id.bytes);
    const text = testContext();
    expect(await runVerify(fixture.tokenFile, { tokenId, trustBase: fixture.trustBaseFile }, text.context)).toBe(
      EXIT_OK,
    );
    expect(text.stdout()).toContain('Lineage id     matches\n');

    const json = testContext({ json: true });
    expect(
      await runVerify(
        fixture.tokenFile,
        { hash: THIRD_DIGEST_HEX, tokenId: `0x${tokenId.toUpperCase()}`, trustBase: fixture.trustBaseFile },
        json.context,
      ),
    ).toBe(EXIT_OK);
    expect(json.json()).toMatchObject({ expectedHashMatches: true, expectedTokenIdMatches: true, status: 'OK' });
  });

  it('fails on another lineage than the one it was given', async () => {
    // The finalized copy shares the token id; any other lineage does not.
    const other = HexConverter.encode(new Uint8Array(32).fill(0x5a));
    const text = testContext();
    expect(await runVerify(fixture.tokenFile, { tokenId: other, trustBase: fixture.trustBaseFile }, text.context)).toBe(
      EXIT_VERIFICATION_FAILED,
    );
    const out = text.stdout();
    expect(out).toMatch(/^Status {9}FAIL: Token id mismatch: this is not the lineage you were given\.\n/);
    expect(out).toContain('Lineage id     differs from the token id you were given\n');
    expect(out).toContain('Expected hash  not checked; pass --file or --hash');

    const json = testContext({ json: true });
    expect(await runVerify(fixture.tokenFile, { tokenId: other, trustBase: fixture.trustBaseFile }, json.context)).toBe(
      EXIT_VERIFICATION_FAILED,
    );
    expect(json.json()).toMatchObject({
      expectedHashMatches: null,
      expectedTokenIdMatches: false,
      reason: 'Token id mismatch: this is not the lineage you were given.',
      status: 'FAIL',
    });
  });

  it('refuses a malformed token id before reading anything, as a usage error', async () => {
    await expect(runVerify('/no/such/token', { tokenId: 'abcd' }, testContext().context)).rejects.toMatchObject({
      exitCode: EXIT_USAGE,
      message: "--token-id must be a token id of 64 hex characters, got 'abcd'.",
    });
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

describe('verify output for a document lineage', () => {
  const bundled = { kind: 'bundled', network: 'testnet2' } as const;
  const override = { kind: 'file', path: '/tmp/rogue.json' } as const;
  let fixture: ILineageFixture;

  beforeAll(async () => {
    fixture = await createLineageFixture();
  });

  /** A verification outcome for the open lineage, OK unless overridden. */
  function result(changes: Partial<ILineageVerificationResult> = {}): ILineageVerificationResult {
    return {
      description: describeLineage(fixture.token),
      details: null,
      matchingRevisions: null,
      reason: null,
      status: 'OK',
      tokenIdMatches: null,
      ...changes,
    };
  }

  it('names the trust base the verdict was reached against', () => {
    const text = lineageVerifyText(result(), bundled);
    expect(text).toMatch(
      /^Status {9}OK {2}\(inclusion proofs, consensus signatures, issuer signature and revision chain verified against the bundled testnet2 trust base\)\n/,
    );
    expect(text).toContain('Trust base     bundled testnet2 pin\n');
    expect(text).toContain('Token type     document lineage\n');
    expect(text).toContain('Revisions      3\n');

    // An override must never be able to present itself as the bundled pin.
    const overridden = lineageVerifyText(result(), override);
    expect(overridden).toContain('verified against /tmp/rogue.json)');
    expect(overridden).toContain('Trust base     /tmp/rogue.json  (override, not the bundled pin)\n');
    expect(overridden).not.toContain('bundled testnet2 trust base');
    expect(lineageVerifyJson(result(), override).trustBase).toEqual({
      bundledNetwork: null,
      path: '/tmp/rogue.json',
      source: 'file',
    });
    expect(lineageVerifyJson(result(), bundled).trustBase).toEqual({
      bundledNetwork: 'testnet2',
      path: null,
      source: 'bundled',
    });
  });

  it.each<[string, readonly number[] | null, string]>([
    ['no digest given', null, 'not checked; pass --file or --hash to find your document in the lineage'],
    ['the latest revision', [2], 'matches revision 2 (the latest)'],
    ['an older revision', [1], 'matches revision 1; superseded by revision 2'],
    ['several revisions', [0, 2], 'matches revisions 0, 2 (the latest)'],
    ['no revision', [], 'differs from every revision'],
  ])('labels the expected hash when it matches %s', (_, matchingRevisions, label) => {
    expect(lineageVerifyText(result({ matchingRevisions }), bundled)).toContain(`Expected hash  ${label}\n`);
  });

  it('labels a match on the seal as the final revision', () => {
    const final = result({ description: describeLineage(fixture.sealed), matchingRevisions: [3] });
    expect(lineageVerifyText(final, bundled)).toContain('Expected hash  matches revision 3 (the final)\n');
    expect(lineageVerifyJson(final, bundled)).toMatchObject({ finalized: true, nextProducer: null });
  });

  it('reports a failure with its reason and the result tree', () => {
    const details = new VerificationResult('LineageTokenVerification', VerificationStatus.FAIL, '', [
      new VerificationResult(
        'Revision[1]SealBurned',
        VerificationStatus.FAIL,
        'Revision 1 is a seal, but is not burned.',
      ),
    ]);
    const failed = result({ details, reason: 'Revision 1 is a seal, but is not burned.', status: 'FAIL' });

    const text = lineageVerifyText(failed, bundled);
    expect(text).toMatch(/^Status {9}FAIL: Revision 1 is a seal, but is not burned\.\n/);
    expect(text).toContain('Expected hash  not checked; verification failed\n');
    expect(text).toContain('Revision[1]SealBurned');
    expect(text.endsWith(details.toString())).toBe(true);

    expect(lineageVerifyJson(failed, bundled)).toMatchObject({
      command: 'verify',
      details: {
        results: [
          { message: 'Revision 1 is a seal, but is not burned.', rule: 'Revision[1]SealBurned', status: 'FAIL' },
        ],
        rule: 'LineageTokenVerification',
        status: 'FAIL',
      },
      expectedHashMatches: null,
      matchingRevisions: null,
      reason: 'Revision 1 is a seal, but is not burned.',
      status: 'FAIL',
      tokenType: 'lineage',
    });
  });

  it('reports a failure before any result tree without one', () => {
    const failed = result({ reason: null, status: 'FAIL' });
    const text = lineageVerifyText(failed, null);
    expect(text).toMatch(/^Status {9}FAIL: verification failed\n/);
    expect(text).toContain('Trust base     none selected\n');
    // Ends with the last revision, not with an empty result tree.
    expect(text).toMatch(/ {2}Round {8}\d+ {2}\(round timestamp \d+, epoch \d+\)$/);
    expect(lineageVerifyJson(failed, null)).toMatchObject({ details: null, trustBase: null });
  });

  it.each<[string, Partial<ILineageVerificationResult>, string]>([
    ['no id given', {}, 'not checked; pass --token-id to tie this to the lineage you were given'],
    ['verification failed first', { reason: 'x', status: 'FAIL' }, 'not checked; verification failed'],
    ['the id matches', { tokenIdMatches: true }, 'matches'],
    [
      'the id differs',
      { reason: 'x', status: 'FAIL', tokenIdMatches: false },
      'differs from the token id you were given',
    ],
  ])('labels the lineage id when %s', (_, changes, label) => {
    expect(lineageVerifyText(result(changes), bundled)).toContain(`Lineage id     ${label}\n`);
  });

  it('does not blame a wrong lineage id on verification in the hash label, nor the reverse', () => {
    const wrongId = result({ reason: 'x', status: 'FAIL', tokenIdMatches: false });
    expect(lineageVerifyText(wrongId, bundled)).toContain(
      'Expected hash  not checked; pass --file or --hash to find your document in the lineage\n',
    );
    const wrongHash = result({ matchingRevisions: [], reason: 'x', status: 'FAIL' });
    expect(lineageVerifyText(wrongHash, bundled)).toContain(
      'Lineage id     not checked; pass --token-id to tie this to the lineage you were given\n',
    );
  });

  it('reports the lineage id comparison in JSON', () => {
    expect(lineageVerifyJson(result(), bundled).expectedTokenIdMatches).toBeNull();
    expect(lineageVerifyJson(result({ tokenIdMatches: true }), bundled).expectedTokenIdMatches).toBe(true);
    expect(lineageVerifyJson(result({ status: 'FAIL', tokenIdMatches: false }), bundled).expectedTokenIdMatches).toBe(
      false,
    );
  });

  it('reports a mismatch as such in JSON', () => {
    expect(lineageVerifyJson(result({ matchingRevisions: [] }), bundled)).toMatchObject({
      expectedHashMatches: false,
      matchingRevisions: [],
    });
    expect(lineageVerifyJson(result({ matchingRevisions: [0, 2] }), bundled)).toMatchObject({
      expectedHashMatches: true,
      matchingRevisions: [0, 2],
    });
  });
});
