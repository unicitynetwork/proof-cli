import { createHash } from 'node:crypto';

import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { CertificationResponse } from '@unicitylabs/state-transition-sdk/lib/api/CertificationResponse.js';
import type { IAggregatorClient } from '@unicitylabs/state-transition-sdk/lib/api/IAggregatorClient.js';
import { InclusionProofResponse } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProofResponse.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import {
  appendRevision,
  createLineage,
  currentProducerKey,
  deriveGenesisSalt,
  isFinalized,
  LineageError,
} from '../../../src/lib/LineageClient.js';
import { LINEAGE_TOKEN_TYPE_HEX, LineageRevision } from '../../../src/lib/LineagePayload.js';
import { verifyLineage } from '../../../src/lib/LineageVerification.js';
import { bundledTrustBase } from '../../../src/lib/networks.js';
import { stampWith } from '../../../src/lib/TimestampClient.js';
import { OTHER_DIGEST, TEST_DIGEST } from '../../support/fixtures.js';
import { TestAggregatorClient } from '../../support/TestAggregatorClient.js';

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

describe('LineageClient', () => {
  // A fresh aggregator per test: a genesis is deterministic in its issuer, digest
  // and recipient, so tests sharing one would all continue the same lineage.
  let aggregator: TestAggregatorClient;
  let counting: CountingClient;
  let client: StateTransitionClient;
  let trustBase: RootTrustBase;

  beforeEach(() => {
    aggregator = TestAggregatorClient.create();
    counting = new CountingClient(aggregator);
    client = new StateTransitionClient(counting);
    trustBase = aggregator.rootTrustBase;
  });
  const fast = { pollIntervalMs: 10, timeoutMs: 2_000 };

  const alice = SigningService.generatePrivateKey();
  const bob = SigningService.generatePrivateKey();
  const carol = SigningService.generatePrivateKey();
  const publicKey = (key: Uint8Array): Uint8Array => new SigningService(key).publicKey;
  const THIRD_DIGEST = new Uint8Array(createHash('sha256').update('v2').digest());

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

  it('replays an interrupted genesis identically, so running it again recovers the lineage', async () => {
    const before = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    // Same issuer, digest and recipient: the same salt, so the aggregator already holds this mint.
    const again = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    expect(HexConverter.encode(again.toCBOR())).toEqual(HexConverter.encode(before.toCBOR()));
  });

  it('derives a different token id from a different issuer, digest or recipient', async () => {
    const id = async (issuer: Uint8Array, digest: Uint8Array, next: Uint8Array | null): Promise<string> =>
      HexConverter.encode((await createLineage(client, trustBase, digest, issuer, next, fast)).id.bytes);
    const base = await id(alice, TEST_DIGEST, publicKey(bob));
    const others = [
      await id(carol, TEST_DIGEST, publicKey(bob)),
      await id(alice, OTHER_DIGEST, publicKey(bob)),
      await id(alice, TEST_DIGEST, publicKey(carol)),
      await id(alice, TEST_DIGEST, null),
    ];
    expect(new Set([base, ...others]).size).toBe(5);
  });

  it('keeps the salt secret to the issuer: it depends on the private key', async () => {
    const recipient = EncodedPredicate.fromPredicate(SignaturePredicate.create(publicKey(bob)));
    const auxData = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
    const salt = await deriveGenesisSalt(alice, recipient, auxData);
    expect(salt.toBytes()).toHaveLength(32);
    expect((await deriveGenesisSalt(alice, recipient, auxData)).equals(salt)).toBe(true);
    expect((await deriveGenesisSalt(carol, recipient, auxData)).equals(salt)).toBe(false);
    // Pinned: the issuer's *private* key goes in, so nobody else can compute the
    // token id before the genesis is certified and mint into its slot first.
    const expected = createHash('sha256')
      .update(
        CborSerializer.encodeArray(
          CborSerializer.encodeTextString('unicity-document-lineage/salt'),
          CborSerializer.encodeByteString(alice),
          recipient.toCBOR(),
          CborSerializer.encodeByteString(auxData),
        ),
      )
      .digest();
    expect(salt.toBytes()).toEqual(new Uint8Array(expected));
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
  });
});
