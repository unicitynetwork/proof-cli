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
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { StateAlreadyCertifiedError } from '../../../src/lib/errors.js';
import {
  appendRevision,
  certifyRevision,
  createLineage,
  createOrRecoverLineage,
  currentProducerKey,
  deriveGenesisSalt,
  findSuccessor,
  isFinalized,
  isSameRevision,
  LineageError,
  prepareRevision,
  recoverRevision,
} from '../../../src/lib/LineageClient.js';
import { LINEAGE_TOKEN_TYPE_HEX, LineageRevision } from '../../../src/lib/LineagePayload.js';
import { createLineageVerificationContext, verifyLineage } from '../../../src/lib/LineageVerification.js';
import { bundledTrustBase } from '../../../src/lib/networks.js';
import { findCertifiedProof, STATE_ID_EXISTS_STATUS, stampWith } from '../../../src/lib/TimestampClient.js';
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

/**
 * An aggregator that already holds an earlier request for the state, not yet in a
 * round: it answers STATE_ID_EXISTS, and certifies the earlier request only from
 * the second proof lookup on.
 */
class LateRoundClient implements IAggregatorClient {
  private lookups = 0;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly earlier: CertificationData,
  ) {}

  public async getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    this.lookups += 1;
    if (this.lookups === 2) {
      await this.inner.submitCertificationRequest(this.earlier);
    }
    return this.inner.getInclusionProof(stateId);
  }

  public submitCertificationRequest(): Promise<CertificationResponse> {
    return Promise.resolve(CertificationResponse.create(STATE_ID_EXISTS_STATUS));
  }
}

/** Shows nothing on the first `misses` proof lookups, as if the earlier request were still in its round. */
class MissingLookupsClient implements IAggregatorClient {
  private lookups = 0;

  public constructor(
    private readonly inner: TestAggregatorClient,
    private readonly misses: number,
  ) {}

  public async getInclusionProof(stateId: StateId): Promise<InclusionProofResponse> {
    this.lookups += 1;
    const response = await this.inner.getInclusionProof(stateId);
    return this.lookups <= this.misses
      ? InclusionProofResponse.notCertified(1n, response.unicityCertificate)
      : response;
  }

  public submitCertificationRequest(certificationData: CertificationData): Promise<CertificationResponse> {
    return this.inner.submitCertificationRequest(certificationData);
  }
}

/** Fails every proof lookup, so a test can see that none was made. */
class NoLookupClient implements IAggregatorClient {
  public getInclusionProof(): Promise<InclusionProofResponse> {
    return Promise.reject(new Error('no lookup expected'));
  }

  public submitCertificationRequest(): Promise<CertificationResponse> {
    return Promise.reject(new Error('no submission expected'));
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
    // Same inputs against the same starting state: the aggregator answers STATE_ID_EXISTS,
    // and the proof it holds is this transfer's, so the replay completes without a warning.
    const warnings: string[] = [];
    const again = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), {
      ...fast,
      onWarning: (message) => warnings.push(message),
    });
    expect(HexConverter.encode(again.toCBOR())).toEqual(HexConverter.encode(first.toCBOR()));
    expect(warnings).toEqual([]);
  });

  describe('a revision slot that is already certified', () => {
    it('says so, with ALREADY_CERTIFIED, when another transfer took the slot', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
      const attempt = appendRevision(client, trustBase, genesis, THIRD_DIGEST, bob, publicKey(carol), fast);
      await expect(attempt).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
      await expect(attempt).rejects.toThrow(
        /^Revision 1 of this lineage was already certified with different content.*that run's digest and next producer/,
      );
    });

    it('recovers a transfer the aggregator certified, without a key or a submission', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const prepared = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      expect(await recoverRevision(client, trustBase, genesis, prepared.transaction, fast)).toBeNull();

      const certified = await certifyRevision(client, trustBase, genesis, prepared, fast);
      const submissions = counting.submissions;
      const recovered = await recoverRevision(client, trustBase, genesis, prepared.transaction, fast);
      expect(counting.submissions).toBe(submissions);
      expect(HexConverter.encode(recovered!.toCBOR())).toEqual(HexConverter.encode(certified.toCBOR()));

      const other = await prepareRevision(genesis, trustBase, THIRD_DIGEST, bob, publicKey(carol));
      await expect(recoverRevision(client, trustBase, genesis, other.transaction, fast)).rejects.toMatchObject({
        code: 'ALREADY_CERTIFIED',
      });
    });

    it('tells whether a transfer is the revision a digest and next producer make', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const { transaction } = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      expect(await isSameRevision(transaction, 1n, OTHER_DIGEST, publicKey(carol))).toBe(true);
      expect(await isSameRevision(transaction, 1n, THIRD_DIGEST, publicKey(carol))).toBe(false);
      expect(await isSameRevision(transaction, 1n, OTHER_DIGEST, publicKey(alice))).toBe(false);
      expect(await isSameRevision(transaction, 1n, OTHER_DIGEST, null)).toBe(false);
      expect(await isSameRevision(transaction, 2n, OTHER_DIGEST, publicKey(carol))).toBe(false);
    });

    it('waits for an earlier request still in its round, and recovers it if it is this one', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const prepared = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      const late = new StateTransitionClient(new LateRoundClient(aggregator, prepared.certificationData));
      const token = await certifyRevision(late, trustBase, genesis, prepared, fast);
      expect(token.transactions).toHaveLength(1);
    });

    it('waits for an earlier request still in its round, and reports it if it is another', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const other = await prepareRevision(genesis, trustBase, THIRD_DIGEST, bob, publicKey(carol));
      const late = new StateTransitionClient(new LateRoundClient(aggregator, other.certificationData));
      const prepared = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      await expect(certifyRevision(late, trustBase, genesis, prepared, fast)).rejects.toMatchObject({
        code: 'ALREADY_CERTIFIED',
      });
    });

    // A gateway can claim another transaction took the slot; only a proof that
    // authenticates under the trust base is believed.
    it('does not take an unauthenticated proof of another transfer for a taken slot', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const elsewhere = TestAggregatorClient.create();
      const other = await prepareRevision(genesis, trustBase, THIRD_DIGEST, bob, publicKey(carol));
      await elsewhere.submitCertificationRequest(other.certificationData);
      const forging = new StateTransitionClient(elsewhere);
      const mine = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      await expect(
        findCertifiedProof(forging, createLineageVerificationContext(trustBase), mine.transaction),
      ).resolves.toBeNull();
      // The same proof under its own trust base is a genuine taken slot.
      await expect(
        findCertifiedProof(forging, createLineageVerificationContext(elsewhere.rootTrustBase), mine.transaction),
      ).rejects.toBeInstanceOf(StateAlreadyCertifiedError);
    });
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
      appendRevision(client, trustBase, genesis, THIRD_DIGEST, bob, publicKey(carol), fast),
    ).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
  });

  // Another client with the producer's key can set its own deadline. The conflict
  // must be checked against that deadline, not this transfer's, or it looks
  // uncertified and the run ends in the SDK's plain hash-mismatch error.
  it('recognises a conflicting transfer that carries its own deadline', async () => {
    const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
    const expiresAt = BigInt(Math.floor(Date.now() / 1000)) + 600n;
    const conflicting = await TransferTransaction.create(
      genesis,
      BurnPredicate.create(new Uint8Array(32)),
      StateMask.generate(),
      { data: new Uint8Array([1]), expiresAt },
    );
    const certificationData = await CertificationData.fromTransaction(
      conflicting,
      await SignaturePredicateUnlockScript.create(conflicting, new SigningService(bob)),
    );
    expect(certificationData.expiresAt).toBe(expiresAt);
    expect((await aggregator.submitCertificationRequest(certificationData)).status).toEqual('SUCCESS');
    await expect(
      appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast),
    ).rejects.toMatchObject({ code: 'ALREADY_CERTIFIED' });
  });

  describe('recovering a genesis', () => {
    it('tells a fresh genesis from one an earlier run certified, which it recovers without submitting', async () => {
      const fresh = await createOrRecoverLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      expect(fresh.recovered).toBe(false);
      const submissions = counting.submissions;
      const again = await createOrRecoverLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      expect(again.recovered).toBe(true);
      expect(counting.submissions).toBe(submissions);
      expect(HexConverter.encode(again.token.id.bytes)).toEqual(HexConverter.encode(fresh.token.id.bytes));
    });

    // One miss: the lookup before submitting. Two: the one after STATE_ID_EXISTS too,
    // so the proof only arrives while waiting for it.
    it.each([1, 2])('counts STATE_ID_EXISTS for this very mint as a recovery (%i missed lookups)', async (misses) => {
      await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const missing = new StateTransitionClient(new MissingLookupsClient(aggregator, misses));
      const replays: string[] = [];
      const again = await createOrRecoverLineage(missing, trustBase, TEST_DIGEST, alice, publicKey(bob), {
        ...fast,
        onAlreadyCertified: () => replays.push('genesis'),
      });
      expect(again.recovered).toBe(true);
      expect(replays).toEqual(['genesis']);
    });

    it('reports a replayed append through onAlreadyCertified, and a fresh one not', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const replays: number[] = [];
      const options = { ...fast, onAlreadyCertified: (): number => replays.push(1) };
      await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), options);
      expect(replays).toEqual([]);
      await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), options);
      expect(replays).toEqual([1]);
    });
  });

  describe('findSuccessor', () => {
    it('finds no successor until the next revision is certified, then proves it', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      expect(await findSuccessor(client, trustBase, genesis)).toEqual({ kind: 'none' });

      const next = await appendRevision(client, trustBase, genesis, OTHER_DIGEST, bob, publicKey(carol), fast);
      const lookup = await findSuccessor(client, trustBase, genesis);
      expect(lookup.kind).toEqual('spent');
      expect(lookup.kind === 'spent' && lookup.proof.referenceTime).toBe(next.transactions[0].referenceTime);
      // The lookup follows the token's own tip.
      expect(await findSuccessor(client, trustBase, next)).toEqual({ kind: 'none' });
    });

    it('does not look up a finalized lineage, which nothing can follow', async () => {
      const sealed = await createLineage(client, trustBase, TEST_DIGEST, alice, null, fast);
      const nobody = new StateTransitionClient(new NoLookupClient());
      expect(await findSuccessor(nobody, trustBase, sealed)).toEqual({ kind: 'none' });
    });

    it('does not believe a proof that does not verify against the trust base', async () => {
      const genesis = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const elsewhere = TestAggregatorClient.create();
      const forged = await prepareRevision(genesis, trustBase, OTHER_DIGEST, bob, publicKey(carol));
      await elsewhere.submitCertificationRequest(forged.certificationData);
      const forging = new StateTransitionClient(elsewhere);
      expect(await findSuccessor(forging, trustBase, genesis)).toEqual({ kind: 'unverified' });
      expect((await findSuccessor(forging, elsewhere.rootTrustBase, genesis)).kind).toEqual('spent');
    });
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
