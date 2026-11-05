import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { runInspect } from '../../src/commands/inspect.js';
import { EXIT_OK } from '../../src/errors.js';
import {
  describeLineage,
  ILineageDescription,
  ILineageRevisionDescription,
} from '../../src/lib/LineageVerification.js';
import { describeToken } from '../../src/lib/TimestampVerification.js';
import {
  descriptionJson,
  ILineageRevisionJson,
  inspectText,
  lineageDescriptionJson,
  lineageInspectJson,
  lineageInspectText,
} from '../../src/output.js';
import { testContext } from '../support/context.js';
import { OTHER_DIGEST_HEX, TEST_DIGEST, TEST_DIGEST_HEX, TEST_PUBLIC_KEY_HEX } from '../support/fixtures.js';
import { createLineageFixture, ILineageFixture, SEAL_DIGEST_HEX } from '../support/LineageFixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';
import { createTimestampToken } from '../support/TimestampFixtures.js';

describe('runInspect on a document lineage', () => {
  let fixture: ILineageFixture;

  beforeAll(async () => {
    fixture = await createLineageFixture();
  });

  it('inspects the lineage without verifying it', async () => {
    const text = testContext();
    expect(await runInspect(fixture.tokenFile, text.context)).toBe(EXIT_OK);
    expect(text.stdout()).toMatch(/^UNVERIFIED {5}/);
    expect(text.stdout()).toContain('Revisions      3\n');

    const json = testContext({ json: true });
    expect(await runInspect(fixture.tokenFile, json.context)).toBe(EXIT_OK);
    const output = json.json() as { revisions: { index: string; signer: string }[] };
    expect(output).toMatchObject({
      command: 'inspect',
      finalized: false,
      issuer: TEST_PUBLIC_KEY_HEX,
      network: { id: 3 },
      nextProducer: fixture.bobPublicHex,
      tokenId: HexConverter.encode(fixture.token.id.bytes),
      tokenType: 'lineage',
      verified: false,
    });
    expect(output.revisions.map((revision) => [revision.index, revision.signer])).toEqual([
      ['0', TEST_PUBLIC_KEY_HEX],
      ['1', fixture.bobPublicHex],
      ['2', TEST_PUBLIC_KEY_HEX],
    ]);
  });

  it('inspects a finalized lineage and says so', async () => {
    const json = testContext({ json: true });
    expect(await runInspect(fixture.sealedFile, json.context)).toBe(EXIT_OK);
    expect(json.json()).toMatchObject({ finalized: true, nextProducer: null, verified: false });
  });
});

describe('inspect output for a timestamp', () => {
  it('shows the fields under an UNVERIFIED banner', async () => {
    const description = describeToken(await createTimestampToken(TestAggregatorClient.create(), TEST_DIGEST));
    const inspected = inspectText(description);
    expect(inspected.startsWith('UNVERIFIED')).toBe(true);
    expect(inspected).toContain('Token type     timestamp');
    expect(inspected).toContain('Recipient      timestamp burn predicate');
    expect(descriptionJson(description).transferCount).toBe(0);

    // `referenceTimeIso` is typed as an ISO string, so the sentinel for a time
    // no Date can hold belongs in the text output only.
    const hostileTime = { ...description, referenceTime: 10n ** 30n };
    expect(descriptionJson(hostileTime).referenceTimeIso).toBeNull();
    expect(inspectText(hostileTime)).toContain('out of range (1000000000000000000000000000000)');
  });
});

describe('inspect output for a document lineage', () => {
  let fixture: ILineageFixture;
  let open: ILineageDescription;
  let sealed: ILineageDescription;

  beforeAll(async () => {
    fixture = await createLineageFixture();
    open = describeLineage(fixture.token);
    sealed = describeLineage(fixture.sealed);
  });

  /** `open` with revision `position` replaced by `changes`, and the top-level fields by `top`. */
  function edited(
    position: number,
    changes: Partial<ILineageRevisionDescription>,
    top: Partial<ILineageDescription> = {},
  ): ILineageDescription {
    const revisions = open.revisions.map((revision, index) =>
      index === position ? { ...revision, ...changes } : revision,
    );
    return { ...open, revisions, ...top };
  }

  it('lists the lineage and every revision under an UNVERIFIED banner', () => {
    const text = lineageInspectText(open);
    expect(text).toMatch(/^UNVERIFIED {5}fields read from the token; nothing below has been checked\n/);
    expect(text).toContain('Token type     document lineage\n');
    expect(text).toContain('Network        unknown network (3)\n');
    expect(text).toContain(`Token id       ${HexConverter.encode(fixture.token.id.bytes)}\n`);
    expect(text).toContain(`Issuer         ${TEST_PUBLIC_KEY_HEX}\n`);
    expect(text).toContain('Revisions      3\n');
    expect(text).toContain(`Next producer  ${fixture.bobPublicHex}\n`);
    expect(text).toContain(
      `Revision 1     SHA-256 ${OTHER_DIGEST_HEX}\n` +
        `  Signed by    ${fixture.bobPublicHex}\n` +
        `  Passes to    ${TEST_PUBLIC_KEY_HEX}\n` +
        '  Certified at ',
    );
    expect(text).toMatch(/ {2}Round {8}\d+ {2}\(round timestamp \d+, epoch \d+\)/);
    expect(text).not.toContain('(final)');
  });

  it('marks the seal and the finalized lineage', () => {
    const text = lineageInspectText(sealed);
    expect(text).toContain('Next producer  none; the lineage is finalized (sealed and burned)\n');
    expect(text).toContain(`Revision 3     SHA-256 ${SEAL_DIGEST_HEX}  (final)\n`);
    expect(text).toContain('  Passes to    nobody; sealed and burned\n');
  });

  it('says what it cannot read instead of failing', () => {
    expect(lineageInspectText(edited(1, { digest: null, error: 'bad payload', index: null }))).toContain(
      'Revision 1     unreadable (bad payload)\n',
    );
    expect(lineageInspectText(edited(1, { digest: null, error: null, index: null }))).toContain(
      'Revision 1     unreadable (no revision payload)\n',
    );
    expect(lineageInspectText(edited(2, { index: 5n }))).toContain('  (claims index 5)\n');
    expect(lineageInspectText(edited(0, { signer: null }))).toContain('  Signed by    not a signature predicate key\n');
    expect(lineageInspectText(edited(0, {}, { issuer: null }))).toContain('Issuer         unreadable genesis reason\n');
  });

  it('names what an unusual recipient is', () => {
    const otherPredicate = lineageInspectText(edited(2, { nextProducer: null }));
    expect(otherPredicate).toContain('  Passes to    not a signature predicate\n');
    expect(otherPredicate).toContain('Next producer  not a signature predicate\n');
    expect(
      lineageInspectText(edited(2, { burnReason: new Uint8Array(32), nextProducer: null, sealed: false })),
    ).toContain('  Passes to    burn predicate, but the revision is not a seal\n');
  });

  it('renders the same fields as JSON', () => {
    const json = lineageInspectJson(open);
    expect(json).toMatchObject({
      command: 'inspect',
      finalized: false,
      issuer: TEST_PUBLIC_KEY_HEX,
      network: { id: 3, name: 'unknown' },
      nextProducer: fixture.bobPublicHex,
      tokenId: HexConverter.encode(fixture.token.id.bytes),
      tokenType: 'lineage',
      verified: false,
    });
    const revision = open.revisions[0];
    expect(json.revisions[0]).toEqual<ILineageRevisionJson>({
      error: null,
      hash: { algorithm: 'SHA-256', digest: TEST_DIGEST_HEX },
      index: '0',
      nextProducer: fixture.bobPublicHex,
      referenceTime: revision.referenceTime.toString(),
      referenceTimeIso: new Date(Number(revision.referenceTime) * 1000).toISOString().replace('.000Z', 'Z'),
      round: {
        epoch: revision.epoch.toString(),
        number: revision.roundNumber.toString(),
        timestamp: revision.roundTimestamp.toString(),
      },
      sealed: false,
      signer: TEST_PUBLIC_KEY_HEX,
    });
  });

  it('renders the seal, unreadable fields and unrepresentable times as JSON nulls', () => {
    const final = lineageDescriptionJson(sealed);
    expect(final.finalized).toBe(true);
    expect(final.nextProducer).toBeNull();
    expect(final.revisions[3]).toMatchObject({ index: '3', nextProducer: null, sealed: true });

    const broken = lineageDescriptionJson(
      edited(
        1,
        {
          digest: null,
          error: 'bad payload',
          index: null,
          nextProducer: null,
          referenceTime: 10n ** 30n,
          signer: null,
        },
        { issuer: null },
      ),
    );
    expect(broken.issuer).toBeNull();
    expect(broken.revisions[1]).toMatchObject({
      error: 'bad payload',
      hash: null,
      index: null,
      nextProducer: null,
      referenceTime: (10n ** 30n).toString(),
      referenceTimeIso: null,
      signer: null,
    });
    // The text keeps the raw value next to the sentinel.
    expect(lineageInspectText(edited(1, { referenceTime: 10n ** 30n }))).toContain(
      'out of range (1000000000000000000000000000000)',
    );
  });
});
