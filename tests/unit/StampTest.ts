import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { describeToken } from '../../src/lib/TimestampVerification.js';
import { stampJson, stampText } from '../../src/output.js';
import { TEST_DIGEST, TEST_DIGEST_HEX } from '../support/fixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';
import { createTimestampToken } from '../support/TimestampFixtures.js';

describe('stamp output', () => {
  it('renders the certified stamp as text and JSON', async () => {
    const token = await createTimestampToken(TestAggregatorClient.create(), TEST_DIGEST);
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
  });
});
