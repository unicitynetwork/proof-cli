import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { runInspect } from '../../src/commands/inspect.js';
import { EXIT_OK } from '../../src/errors.js';
import { describeToken } from '../../src/lib/TimestampVerification.js';
import { descriptionJson, inspectText } from '../../src/output.js';
import { testContext } from '../support/context.js';
import { TEST_DIGEST, TEST_PUBLIC_KEY_HEX } from '../support/fixtures.js';
import { createLineageFixture, ILineageFixture } from '../support/LineageFixtures.js';
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
