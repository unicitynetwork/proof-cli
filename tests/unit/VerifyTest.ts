import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';

import { runVerify } from '../../src/commands/verify.js';
import { EXIT_USAGE, EXIT_VERIFICATION_FAILED } from '../../src/errors.js';
import { stampWith } from '../../src/lib/TimestampClient.js';
import { testContext } from '../support/context.js';
import { tempDir, TEST_DIGEST, TEST_DIGEST_HEX } from '../support/fixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';

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
