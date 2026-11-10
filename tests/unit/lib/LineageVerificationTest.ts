import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import type { IPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/IPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';

import { createLineage } from '../../../src/lib/LineageClient.js';
import {
  LINEAGE_TOKEN_TYPE,
  LineageGenesisReason,
  LineageRevision,
  sealPredicate,
} from '../../../src/lib/LineagePayload.js';
import { describeLineage, verifyLineage } from '../../../src/lib/LineageVerification.js';
import { OTHER_DIGEST, TEST_DIGEST } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';
import { certifyMint } from '../../support/TimestampFixtures.js';

describe('LineageVerification', () => {
  const aggregator = TestAggregatorClient.create();
  const client = new StateTransitionClient(aggregator);
  const trustBase = aggregator.rootTrustBase;
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };

  const alice = SigningService.generatePrivateKey();
  const bob = SigningService.generatePrivateKey();
  const carol = SigningService.generatePrivateKey();
  const publicKey = (key: Uint8Array): Uint8Array => new SigningService(key).publicKey;

  /**
   * Mint a lineage-typed genesis with arbitrary fields and wrap it as a token,
   * bypassing the issuance checks a real mint goes through.
   */
  async function rawLineageToken(
    recipient: IPredicate,
    options: { data?: Uint8Array | null; justification?: Uint8Array | null; salt?: TokenSalt },
  ): Promise<Token> {
    const genesis = await certifyMint(aggregator, recipient, {
      salt: TokenSalt.generate(),
      tokenType: LINEAGE_TOKEN_TYPE,
      ...options,
    });
    return Token.fromCBOR(
      CborSerializer.encodeTag(
        Token.CBOR_TAG,
        CborSerializer.encodeArray(
          CborSerializer.encodeUnsignedInteger(2n),
          genesis.toCBOR(),
          CborSerializer.encodeArray(),
        ),
      ),
    );
  }

  /**
   * A genesis with an issuer signature over `data` and `signedRecipient`, minted
   * to `recipient`; the signature is valid when the two are the same predicate.
   */
  async function signedGenesis(
    data: Uint8Array,
    recipient: IPredicate,
    signedRecipient: IPredicate = recipient,
  ): Promise<Token> {
    const salt = TokenSalt.generate();
    const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
    const reason = await LineageGenesisReason.sign(
      tokenId,
      LINEAGE_TOKEN_TYPE,
      EncodedPredicate.fromPredicate(signedRecipient),
      data,
      new SigningService(alice),
    );
    return rawLineageToken(recipient, { data, justification: reason.toCBOR(), salt });
  }

  describe('genesis', () => {
    it('rejects a genesis whose issuer signature covers another token', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const otherId = await TokenId.fromSalt(trustBase.networkId, TokenSalt.generate());
      const recipient = SignaturePredicate.create(publicKey(bob));
      const reason = await LineageGenesisReason.sign(
        otherId,
        LINEAGE_TOKEN_TYPE,
        EncodedPredicate.fromPredicate(recipient),
        data,
        new SigningService(alice),
      );
      const token = await rawLineageToken(recipient, {
        data,
        justification: reason.toCBOR(),
      });
      const result = await verifyLineage(token, trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Issuer signature in the genesis reason does not verify.');
    });

    it('accepts a genesis minted to the recipient the issuer signed for', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const result = await verifyLineage(
        await signedGenesis(data, SignaturePredicate.create(publicKey(bob))),
        trustBase,
      );
      expect(result.reason).toBeNull();
      expect(result.status).toEqual('OK');
    });

    // A delegated mint: the issuer signs for bob, whoever submits the mint names carol.
    it('rejects a genesis minted to another recipient than the issuer signed for', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const result = await verifyLineage(
        await signedGenesis(
          data,
          SignaturePredicate.create(publicKey(carol)),
          SignaturePredicate.create(publicKey(bob)),
        ),
        trustBase,
      );
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Issuer signature in the genesis reason does not verify.');
    });

    it('rejects a genesis burned at once when the issuer signed for a producer', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const result = await verifyLineage(
        await signedGenesis(data, await sealPredicate(data), SignaturePredicate.create(publicKey(bob))),
        trustBase,
      );
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Issuer signature in the genesis reason does not verify.');
    });

    it('rejects a genesis without an issuer reason', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const token = await rawLineageToken(SignaturePredicate.create(publicKey(bob)), { data, justification: null });
      const result = await verifyLineage(token, trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Lineage genesis carries no issuer reason.');
    });

    it('rejects a genesis that does not start at revision 0', async () => {
      const data = LineageRevision.create(1n, TEST_DIGEST).toCBOR();
      const result = await verifyLineage(
        await signedGenesis(data, SignaturePredicate.create(publicKey(bob))),
        trustBase,
      );
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Genesis revision index is 1, not 0.');
    });
  });

  describe('seal', () => {
    it('accepts a correctly formed seal at genesis', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const result = await verifyLineage(await signedGenesis(data, await sealPredicate(data)), trustBase);
      expect(result.reason).toBeNull();
      expect(result.description.finalized).toBe(true);
    });

    it('rejects a seal that is not burned', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const result = await verifyLineage(
        await signedGenesis(data, SignaturePredicate.create(publicKey(bob))),
        trustBase,
      );
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Revision 0 is a seal, but is not burned.');
    });

    it('rejects a burn that is not a seal', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const result = await verifyLineage(await signedGenesis(data, await sealPredicate(data)), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Revision 0 is burned, but is not a seal.');
    });

    it('rejects a seal whose burn reason commits to something else', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const other = LineageRevision.create(0n, OTHER_DIGEST, true).toCBOR();
      const result = await verifyLineage(await signedGenesis(data, await sealPredicate(other)), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Revision 0 is a seal, but its burn reason does not commit to it.');
    });
  });

  it('describes revisions without verifying', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    const description = describeLineage(genesis);
    expect(description.tokenTypeIsLineage).toBe(true);
    expect(description.finalized).toBe(false);
    expect(description.revisions).toHaveLength(1);
    expect(description.revisions[0].error).toBeNull();
  });
});
