import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { tempDir, OTHER_DIGEST, TEST_DIGEST, TEST_PRIVATE_KEY, TEST_PUBLIC_KEY_HEX } from './fixtures.js';
import { TestAggregatorClient } from './TestAggregatorClient.js';
import { appendRevision, createLineage } from '../../src/lib/LineageClient.js';

/** Digest of revision 2 of the fixture lineage. */
export const THIRD_DIGEST_HEX = 'ab'.repeat(32);

/** Digest of the seal, revision 3, of the finalized fixture lineage. */
export const SEAL_DIGEST_HEX = 'cd'.repeat(32);

export interface ILineageFixture {
  readonly bobPublicHex: string;
  /** The finalized lineage: {@link token} with a seal appended by bob. */
  readonly sealedFile: string;
  /** Three revisions: 0 by the issuer naming bob, 1 by bob naming the issuer, 2 by the issuer naming bob. */
  readonly token: Token;
  readonly tokenFile: string;
  /** Trust base of the in-memory aggregator, whose network id matches no bundled pin. */
  readonly trustBaseFile: string;
}

/**
 * Certify a document lineage on a fresh in-memory aggregator and write it, a
 * finalized copy of it, and the aggregator's trust base to a temporary directory.
 *
 * @returns {Promise<ILineageFixture>} Paths and the open lineage token.
 */
export async function createLineageFixture(): Promise<ILineageFixture> {
  const aggregator = TestAggregatorClient.create();
  const client = new StateTransitionClient(aggregator);
  const trustBase = aggregator.rootTrustBase;
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };
  const bob = SigningService.generatePrivateKey();
  const bobPublic = new SigningService(bob).publicKey;
  const issuerPublic = HexConverter.decode(TEST_PUBLIC_KEY_HEX);

  const genesis = await createLineage(client, trustBase, TEST_DIGEST, TEST_PRIVATE_KEY, bobPublic, fast);
  const first = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, issuerPublic, fast);
  const token = await appendRevision(
    client,
    trustBase,
    first,
    HexConverter.decode(THIRD_DIGEST_HEX),
    TEST_PRIVATE_KEY,
    bobPublic,
    fast,
  );
  const sealed = await appendRevision(client, trustBase, token, HexConverter.decode(SEAL_DIGEST_HEX), bob, null, fast);

  const directory = await tempDir('proof-cli-lineage-');
  const tokenFile = path.join(directory, 'doc.lineage');
  await writeFile(tokenFile, token.toCBOR());
  const sealedFile = path.join(directory, 'sealed.lineage');
  await writeFile(sealedFile, sealed.toCBOR());
  const trustBaseFile = path.join(directory, 'trust-base.json');
  await writeFile(trustBaseFile, JSON.stringify(trustBase.toJSON()));

  return { bobPublicHex: HexConverter.encode(bobPublic), sealedFile, token, tokenFile, trustBaseFile };
}
