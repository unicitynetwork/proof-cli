import { createHash } from 'node:crypto';

import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import type { IPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/IPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { CertifiedTransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedTransferTransaction.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import { createLineage } from '../../../src/lib/LineageClient.js';
import {
  LINEAGE_TOKEN_TYPE,
  LineageGenesisReason,
  LineageRevision,
  sealPredicate,
} from '../../../src/lib/LineagePayload.js';
import {
  createLineageVerificationContext,
  describeLineage,
  verifyLineage,
} from '../../../src/lib/LineageVerification.js';
import { bundledTrustBase } from '../../../src/lib/networks.js';
import { certifyMintTransaction, certifyTransaction } from '../../../src/lib/TimestampClient.js';
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

  describe('chain rules', () => {
    interface IRawTransfer {
      readonly certificationData: CertificationData;
      readonly transaction: TransferTransaction;
    }

    /**
     * A transfer out of the latest state of `source`, with any payload and
     * recipient, signed by `producer`, bypassing the checks appendRevision makes.
     * `source` need only offer its latest transaction, so a transfer can be built
     * on one that is not certified yet.
     */
    async function rawTransfer(
      source: Pick<Token, 'latestTransaction'>,
      producer: Uint8Array,
      data: Uint8Array,
      recipient: IPredicate,
    ): Promise<IRawTransfer> {
      const transaction = await TransferTransaction.create(source as Token, recipient, StateMask.generate(), { data });
      const certificationData = await CertificationData.fromTransaction(
        transaction,
        await SignaturePredicateUnlockScript.create(transaction, new SigningService(producer)),
      );
      return { certificationData, transaction };
    }

    async function certify(raw: IRawTransfer): Promise<CertifiedTransferTransaction> {
      const context = createLineageVerificationContext(trustBase);
      const proof = await certifyTransaction(client, context, raw.certificationData, raw.transaction, fast);
      return raw.transaction.toCertifiedTransaction(
        trustBase,
        context.predicateVerifier,
        context.unicityCertificateVerifier,
        proof,
      );
    }

    async function attach(token: Token, ...transfers: CertifiedTransferTransaction[]): Promise<Token> {
      let result = token;
      for (const transfer of transfers) {
        result = await result.transfer(transfer, createLineageVerificationContext(trustBase));
      }
      return result;
    }

    /** Names of the failing rules anywhere in the result tree. */
    function failedRules(result: VerificationResult<unknown> | null): string[] {
      if (result === null) {
        return [];
      }
      const own = result.status === VerificationStatus.OK ? [] : [result.rule];
      return [...own, ...result.results.flatMap(failedRules)];
    }

    // The aggregator is shared and a genesis is deterministic in its inputs, so each
    // test starts its own lineage from a digest of its own.
    let lineages = 0;
    function freshGenesis(): Promise<Token> {
      lineages += 1;
      const digest = new Uint8Array(createHash('sha256').update(`chain rules ${lineages}`).digest());
      return createLineage(client, trustBase, digest, alice, publicKey(bob), fast);
    }

    const revision = (index: bigint, digest = OTHER_DIGEST): Uint8Array =>
      LineageRevision.create(index, digest).toCBOR();
    const pSig = (key: Uint8Array): IPredicate => SignaturePredicate.create(publicKey(key));

    it('accepts revisions appended in order, the control for the cases below', async () => {
      const genesis = await freshGenesis();
      const first = await rawTransfer(genesis, bob, revision(1n), pSig(carol));
      const second = await rawTransfer({ latestTransaction: first.transaction }, carol, revision(2n), pSig(alice));
      const token = await attach(genesis, await certify(first), await certify(second));
      const result = await verifyLineage(token, trustBase);
      expect(result.reason).toBeNull();
      expect(result.status).toEqual('OK');
    });

    it('rejects a transfer claiming another index than its position', async () => {
      const genesis = await freshGenesis();
      // A producer controls the payload of their own transfer, so a wrong index is a realistic input.
      const skipped = await rawTransfer(genesis, bob, revision(5n), pSig(carol));
      const result = await verifyLineage(await attach(genesis, await certify(skipped)), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Revision at position 1 claims index 5.');
      expect(failedRules(result.details)).toContain('Revision[1]IndexSequential');
    });

    it('rejects a transfer repeating the previous index, further down the chain', async () => {
      const genesis = await freshGenesis();
      const first = await rawTransfer(genesis, bob, revision(1n), pSig(carol));
      const repeat = await rawTransfer({ latestTransaction: first.transaction }, carol, revision(1n), pSig(alice));
      const token = await attach(genesis, await certify(first), await certify(repeat));
      const result = await verifyLineage(token, trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual('Revision at position 2 claims index 1.');
    });

    // States can be precomputed and certified out of order: the protocol links each
    // transfer to the state before it, not to the time it was certified.
    it('rejects a revision certified before the one it follows', async () => {
      const genesis = await freshGenesis();
      const first = await rawTransfer(genesis, bob, revision(1n), pSig(carol));
      const second = await rawTransfer({ latestTransaction: first.transaction }, carol, revision(2n), pSig(alice));
      const certifiedSecond = await certify(second);
      const certifiedFirst = await certify(first);
      expect(certifiedSecond.referenceTime).toBeLessThan(certifiedFirst.referenceTime);

      const result = await verifyLineage(await attach(genesis, certifiedFirst, certifiedSecond), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toEqual(
        `Revision 2 is certified at ${certifiedSecond.referenceTime}, before revision 1 at ${certifiedFirst.referenceTime}.`,
      );
      expect(failedRules(result.details)).toContain('Revision[2]TimeMonotone');
    });

    it('rejects a transfer certified before the genesis it follows', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      // Build the genesis, and the transfer out of it, before certifying either.
      const salt = TokenSalt.generate();
      const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
      const reason = await LineageGenesisReason.sign(
        tokenId,
        LINEAGE_TOKEN_TYPE,
        EncodedPredicate.fromPredicate(pSig(bob)),
        data,
        new SigningService(alice),
      );
      const mint = await MintTransaction.create(trustBase.networkId, pSig(bob), {
        data,
        justification: reason.toCBOR(),
        salt,
        tokenType: LINEAGE_TOKEN_TYPE,
      });
      const first = await rawTransfer({ latestTransaction: mint }, bob, revision(1n), pSig(carol));
      const certifiedFirst = await certify(first);
      const context = createLineageVerificationContext(trustBase);
      const genesis = await Token.mint(await certifyMintTransaction(client, context, mint, fast), context);

      const result = await verifyLineage(await attach(genesis, certifiedFirst), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(result.reason).toMatch(/^Revision 1 is certified at \d+, before revision 0 at \d+\.$/);
    });

    // Defence in depth: a seal is burned and nothing can spend a burn, so a token with
    // a revision after a seal fails other rules first. Here the seal is minted to a key
    // instead, which SealBurned rejects, and SealIsLast must reject it as well.
    it('rejects a seal that revisions follow', async () => {
      const data = LineageRevision.create(0n, TEST_DIGEST, true).toCBOR();
      const genesis = await signedGenesis(data, pSig(bob));
      const next = await rawTransfer(genesis, bob, revision(1n), pSig(carol));
      const result = await verifyLineage(await attach(genesis, await certify(next)), trustBase);
      expect(result.status).toEqual('FAIL');
      expect(failedRules(result.details)).toEqual(
        expect.arrayContaining(['Revision[0]SealBurned', 'Revision[0]SealIsLast']),
      );
    });
  });

  describe('token id', () => {
    it('passes when the lineage is the one with the expected token id', async () => {
      const token = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const result = await verifyLineage(token, trustBase, { expectedTokenId: token.id.bytes });
      expect(result.reason).toBeNull();
      expect(result.status).toEqual('OK');
      expect(result.tokenIdMatches).toBe(true);
      expect((await verifyLineage(token, trustBase)).tokenIdMatches).toBeNull();
    });

    // The shadow lineage from the review of issue #13: same issuer, same first
    // producer, same initial document, but another salt. Both verify on their own,
    // and only the token id tells them apart.
    it('tells a parallel lineage from the same issuer and document apart', async () => {
      const real = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const data = LineageRevision.create(0n, TEST_DIGEST).toCBOR();
      const shadow = await signedGenesis(data, SignaturePredicate.create(publicKey(bob)));
      expect((await verifyLineage(shadow, trustBase)).status).toEqual('OK');
      expect(describeLineage(shadow).issuer).toEqual(describeLineage(real).issuer);

      const result = await verifyLineage(shadow, trustBase, {
        expectedDigest: TEST_DIGEST,
        expectedTokenId: real.id.bytes,
      });
      expect(result.status).toEqual('FAIL');
      expect(result.tokenIdMatches).toBe(false);
      expect(result.reason).toEqual('Token id mismatch: this is not the lineage you were given.');
      // The digest is still compared, so the output can show both.
      expect(result.matchingRevisions).toEqual([0]);
    });

    it('does not compare the token id of a token that fails verification', async () => {
      const token = await createLineage(client, trustBase, TEST_DIGEST, alice, publicKey(bob), fast);
      const result = await verifyLineage(token, bundledTrustBase('mainnet'), { expectedTokenId: token.id.bytes });
      expect(result.status).toEqual('FAIL');
      expect(result.tokenIdMatches).toBeNull();
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
