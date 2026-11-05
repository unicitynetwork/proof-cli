import { createHash } from 'node:crypto';

import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationResponse } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import type { IPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/IPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import {
  appendRevision,
  createLineage,
  currentProducerKey,
  isFinalized,
  LineageError,
} from '../../../src/lib/LineageClient.js';
import {
  LINEAGE_TAG,
  LINEAGE_TOKEN_TYPE,
  LINEAGE_TOKEN_TYPE_HEX,
  LineageFormatError,
  LineageGenesisReason,
  LineageRevision,
  sealPredicate,
} from '../../../src/lib/LineagePayload.js';
import { describeLineage, verifyLineage } from '../../../src/lib/LineageVerification.js';
import { bundledTrustBase } from '../../../src/lib/networks.js';
import { stampWith } from '../../../src/lib/TimestampClient.js';
import { OTHER_DIGEST, TEST_DIGEST } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';
import { certifyMint } from '../../support/TimestampFixtures.js';

/** Counts certification requests so a test can see whether the network was contacted. */
class CountingClient implements IAggregatorClient {
  public submissions = 0;

  public constructor(private readonly inner: TestAggregatorClient) {}

  public getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    return this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    this.submissions += 1;
    return this.inner.submitCertificationRequest(certificationData);
  }
}

describe('document lineage', () => {
  const aggregator = TestAggregatorClient.create();
  const counting = new CountingClient(aggregator);
  const client = new StateTransitionClient(counting);
  const trustBase = aggregator.rootTrustBase;
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };

  const alice = SigningService.generatePrivateKey();
  const bob = SigningService.generatePrivateKey();
  const carol = SigningService.generatePrivateKey();
  const publicKey = (key: Uint8Array): Uint8Array => new SigningService(key).publicKey;
  const THIRD_DIGEST = new Uint8Array(createHash('sha256').update('v2').digest());

  it('pins the token type to SHA-256 of the tag', () => {
    expect(createHash('sha256').update(LINEAGE_TAG).digest('hex')).toEqual(LINEAGE_TOKEN_TYPE_HEX);
  });

  it('creates a lineage, appends revisions along the chain of custody, and verifies offline', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    expect(genesis.transactions).toHaveLength(0);
    expect(HexConverter.encode(genesis.type.bytes)).toEqual(LINEAGE_TOKEN_TYPE_HEX);
    expect(currentProducerKey(genesis)).toEqual(publicKey(bob));

    const second = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
    const third = await appendRevision(
      client,
      trustBase,
      await Token.fromCBOR(second.toCBOR()),
      THIRD_DIGEST,
      carol,
      publicKey(alice),
      fast,
    );

    const result = await verifyLineage(await Token.fromCBOR(third.toCBOR()), trustBase);
    expect(result.reason).toBeNull();
    expect(result.status).toEqual('OK');
    expect(result.description.issuer).toEqual(publicKey(alice));
    expect(result.description.revisions.map((revision) => revision.index)).toEqual([0n, 1n, 2n]);
    expect(result.description.revisions.map((revision) => HexConverter.encode(revision.digest!))).toEqual(
      [TEST_DIGEST, OTHER_DIGEST, THIRD_DIGEST].map((digest) => HexConverter.encode(digest)),
    );
    expect(result.description.revisions.map((revision) => revision.nextProducer)).toEqual([
      publicKey(bob),
      publicKey(carol),
      publicKey(alice),
    ]);
  });

  it('refuses, before contacting the network, a key that is not the named producer', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    const before = counting.submissions;
    const attempt = appendRevision(client, trustBase, genesis, OTHER_DIGEST, alice, publicKey(carol), fast);
    await expect(attempt).rejects.toBeInstanceOf(LineageError);
    await expect(attempt).rejects.toMatchObject({ code: 'WRONG_KEY' });
    expect(counting.submissions).toBe(before);
  });

  it('refuses to append to a token of another type', async () => {
    const stamp = await stampWith(client, trustBase, TEST_DIGEST, fast);
    const attempt = appendRevision(client, trustBase, stamp, OTHER_DIGEST, alice, publicKey(bob), fast);
    await expect(attempt).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
    await expect(attempt).rejects.toThrow(/Not a document lineage token/);
  });

  it('refuses to append to a token from another network', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    await expect(
      appendRevision(client, bundledTrustBase('mainnet'), genesis, OTHER_DIGEST, bob, publicKey(carol), fast),
    ).rejects.toMatchObject({ code: 'INVALID_TOKEN' });
  });

  it('replays an interrupted step identically, so running it again recovers the revision', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    const first = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
    // Same inputs against the same starting state: the aggregator already holds this request.
    const again = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
    expect(HexConverter.encode(again.toCBOR())).toEqual(HexConverter.encode(first.toCBOR()));
  });

  it('cannot fork: a different successor of a spent state is never certified', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
    await expect(
      appendRevision(client, trustBase, genesis, THIRD_DIGEST, bob, publicKey(carol), {
        pollIntervalMs: 10,
        timeoutMs: 300,
      }),
    ).rejects.toThrow();
  });

  describe('finalization', () => {
    it('seals the final revision and burns the token, so nothing can follow', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const sealed = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, null, fast);
      const token = await Token.fromCBOR(sealed.toCBOR());
      expect(isFinalized(token)).toBe(true);
      expect(isFinalized(genesis)).toBe(false);
      expect(currentProducerKey(token)).toBeNull();

      const payload = token.transactions[0].data as Uint8Array;
      const revision = LineageRevision.fromCBOR(payload);
      expect(revision.sealed).toBe(true);
      expect(revision.index).toBe(1n);
      expect(revision.digest).toEqual(OTHER_DIGEST);
      // The burn reason commits to the seal: P_burn(H(b_seal)).
      expect(BurnPredicate.fromPredicate(token.transactions[0].recipient).reason).toEqual(
        new Uint8Array(createHash('sha256').update(payload).digest()),
      );

      const result = await verifyLineage(token, trustBase, { expectedDigest: OTHER_DIGEST });
      expect(result.reason).toBeNull();
      expect(result.status).toEqual('OK');
      expect(result.description.finalized).toBe(true);
      expect(result.description.revisions.map((entry) => entry.sealed)).toEqual([false, true]);

      const before = counting.submissions;
      for (const key of [alice, bob, carol]) {
        await expect(
          appendRevision(client, trustBase, token, THIRD_DIGEST, key, publicKey(carol), fast),
        ).rejects.toMatchObject({ code: 'FINALIZED' });
      }
      expect(counting.submissions).toBe(before);
    });

    it('finalizes a new lineage at revision 0', async () => {
      const token = await createLineage(client, trustBase, TEST_DIGEST, alice, null, fast);
      expect(isFinalized(token)).toBe(true);
      const result = await verifyLineage(await Token.fromCBOR(token.toCBOR()), trustBase);
      expect(result.reason).toBeNull();
      expect(result.description.finalized).toBe(true);
      expect(result.description.revisions[0].signer).toEqual(publicKey(alice));
      await expect(
        appendRevision(client, trustBase, token, OTHER_DIGEST, alice, publicKey(bob), fast),
      ).rejects.toMatchObject({ code: 'FINALIZED' });
    });

    it('replays an interrupted seal identically', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const first = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, null, fast);
      const again = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, null, fast);
      expect(HexConverter.encode(again.toCBOR())).toEqual(HexConverter.encode(first.toCBOR()));
    });

    /** A genesis with a valid issuer signature over `data`, minted to `recipient`. */
    async function signedGenesis(data: Uint8Array, recipient: IPredicate): Promise<Token> {
      const salt = TokenSalt.generate();
      const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
      const reason = await LineageGenesisReason.sign(tokenId, LINEAGE_TOKEN_TYPE, data, new SigningService(alice));
      const genesis = await certifyMint(aggregator, recipient, {
        data,
        justification: reason.toCBOR(),
        salt,
        tokenType: LINEAGE_TOKEN_TYPE,
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

    it('accepts a correctly formed seal at genesis', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const result = await verifyLineage(await signedGenesis(data, await sealPredicate(data)), trustBase);
      expect(result.reason).toBeNull();
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

  describe('verification', () => {
    /** Mint a lineage-typed genesis with arbitrary fields and wrap it as a token, bypassing issuance checks. */
    async function rawLineageToken(options: {
      data?: Uint8Array | null;
      justification?: Uint8Array | null;
    }): Promise<Token> {
      const salt = TokenSalt.generate();
      const genesis = await certifyMint(aggregator, SignaturePredicate.create(publicKey(bob)), {
        salt,
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

    it('rejects a genesis whose issuer signature covers another token', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const otherId = await TokenId.fromSalt(trustBase.networkId, TokenSalt.generate());
      const reason = await LineageGenesisReason.sign(otherId, LINEAGE_TOKEN_TYPE, data, new SigningService(alice));
      const result = await verifyLineage(await rawLineageToken({ data, justification: reason.toCBOR() }), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Issuer signature in the genesis reason does not verify.');
    });

    it('rejects a genesis without an issuer reason', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const result = await verifyLineage(await rawLineageToken({ data, justification: null }), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Lineage genesis carries no issuer reason.');
    });

    it('rejects a genesis that does not start at revision 0', async () => {
      const salt = TokenSalt.generate();
      const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
      const data = LineageRevision.create(1n, TEST_DIGEST).toCBOR();
      const reason = await LineageGenesisReason.sign(tokenId, LINEAGE_TOKEN_TYPE, data, new SigningService(alice));
      const genesis = await certifyMint(aggregator, SignaturePredicate.create(publicKey(bob)), {
        data,
        justification: reason.toCBOR(),
        salt,
        tokenType: LINEAGE_TOKEN_TYPE,
      });
      const token = await Token.fromCBOR(
        CborSerializer.encodeTag(
          Token.CBOR_TAG,
          CborSerializer.encodeArray(
            CborSerializer.encodeUnsignedInteger(2n),
            genesis.toCBOR(),
            CborSerializer.encodeArray(),
          ),
        ),
      );
      const result = await verifyLineage(token, trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Genesis revision index is 1, not 0.');
    });

    it('describes revisions without verifying', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const description = describeLineage(genesis);
      expect(description.tokenTypeIsLineage).toBe(true);
      expect(description.revisions).toHaveLength(1);
      expect(description.revisions[0].error).toBeNull();
    });
  });

  describe('payload encoding', () => {
    it('round-trips a revision', () => {
      const revision = LineageRevision.create(3n, TEST_DIGEST);
      const decoded = LineageRevision.fromCBOR(revision.toCBOR());
      expect(decoded.index).toBe(3n);
      expect(decoded.digest).toEqual(TEST_DIGEST);
    });

    it('rejects malformed revisions', () => {
      expect(() => LineageRevision.create(0n, new Uint8Array(31))).toThrow(LineageFormatError);
      expect(() =>
        LineageRevision.fromCBOR(CborSerializer.encodeArray(CborSerializer.encodeUnsignedInteger(0n))),
      ).toThrow(LineageFormatError);
      const trailing = new Uint8Array([...LineageRevision.create(0n, TEST_DIGEST).toCBOR(), 0x00]);
      expect(() => LineageRevision.fromCBOR(trailing)).toThrow(LineageFormatError);
    });

    it('round-trips a seal and keeps it distinct from an ordinary revision', () => {
      const seal = LineageRevision.create(3n, TEST_DIGEST, true);
      const decoded = LineageRevision.fromCBOR(seal.toCBOR());
      expect(decoded.sealed).toBe(true);
      expect(decoded.index).toBe(3n);
      expect(decoded.digest).toEqual(TEST_DIGEST);
      expect(LineageRevision.fromCBOR(LineageRevision.create(3n, TEST_DIGEST).toCBOR()).sealed).toBe(false);
      expect(HexConverter.encode(seal.toCBOR())).toEqual(
        `8364${HexConverter.encode(new TextEncoder().encode('seal'))}035820${HexConverter.encode(TEST_DIGEST)}`,
      );
    });

    it('rejects a three-element revision without the seal marker', () => {
      const bogus = CborSerializer.encodeArray(
        CborSerializer.encodeTextString('stop'),
        CborSerializer.encodeUnsignedInteger(0n),
        CborSerializer.encodeByteString(TEST_DIGEST),
      );
      expect(() => LineageRevision.fromCBOR(bogus)).toThrow(LineageFormatError);
    });

    it('round-trips a genesis reason and rejects a wrong tag', async () => {
      const tokenId = await TokenId.fromSalt(trustBase.networkId, TokenSalt.generate());
      const reason = await LineageGenesisReason.sign(
        tokenId,
        LINEAGE_TOKEN_TYPE,
        TEST_DIGEST,
        new SigningService(alice),
      );
      const decoded = LineageGenesisReason.fromCBOR(reason.toCBOR());
      expect(decoded.issuer).toEqual(publicKey(alice));
      expect(await decoded.verify(tokenId, LINEAGE_TOKEN_TYPE, TEST_DIGEST)).toBe(true);
      expect(await decoded.verify(tokenId, LINEAGE_TOKEN_TYPE, OTHER_DIGEST)).toBe(false);

      const wrongTag = CborSerializer.encodeTag(1n, CborSerializer.encodeArray());
      expect(() => LineageGenesisReason.fromCBOR(wrongTag)).toThrow(LineageFormatError);
    });

    it('builds the recipient as a P_sig predicate', () => {
      const predicate = EncodedPredicate.fromPredicate(SignaturePredicate.create(publicKey(bob)));
      expect(SignaturePredicate.fromPredicate(predicate).publicKey).toEqual(publicKey(bob));
    });
  });
});
