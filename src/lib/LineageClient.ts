import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { InclusionProof } from '@unicitylabs/state-transition-sdk/lib/api/InclusionProof.js';
import { JsonRpcNetworkError } from '@unicitylabs/state-transition-sdk/lib/api/json-rpc/JsonRpcNetworkError.js';
import { StateId } from '@unicitylabs/state-transition-sdk/lib/api/StateId.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import {
  InclusionProofVerificationRule,
  InclusionProofVerificationStatus,
} from '@unicitylabs/state-transition-sdk/lib/transaction/verification/rule/InclusionProofVerificationRule.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';

import { StateAlreadyCertifiedError } from './errors.js';
import {
  LINEAGE_TAG,
  LINEAGE_TOKEN_TYPE,
  LineageGenesisReason,
  LineageRevision,
  sealPredicate,
} from './LineagePayload.js';
import { createLineageVerificationContext, verifyLineage } from './LineageVerification.js';
import { ICertifyOptions, certifyTransaction, findCertifiedProof } from './TimestampClient.js';

/** Thrown when a revision cannot be appended to the given token with the given key. */
export class LineageError extends Error {
  public constructor(
    message: string,
    /**
     * `INVALID_TOKEN`: the token does not verify as a lineage; `WRONG_KEY`: the key
     * cannot append to it; `FINALIZED`: the lineage is sealed and nothing can;
     * `ALREADY_CERTIFIED`: this revision slot was already certified with other content;
     * `SUPERSEDED`: a recovered genesis whose lineage has moved on since.
     */
    public readonly code: 'ALREADY_CERTIFIED' | 'FINALIZED' | 'INVALID_TOKEN' | 'SUPERSEDED' | 'WRONG_KEY',
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = 'LineageError';
  }
}

/**
 * Public key of the `P_sig` predicate the token's latest state is locked to.
 *
 * @param {Token} token Lineage token.
 * @returns {Uint8Array|null} The key, or null when the state is locked to another kind of predicate.
 */
export function currentProducerKey(token: Token): Uint8Array | null {
  try {
    return SignaturePredicate.fromPredicate(token.latestTransaction.recipient).publicKey;
  } catch {
    return null;
  }
}

/**
 * Whether the token's latest state is locked to the burn predicate, which for a
 * valid lineage means its latest revision is a seal.
 *
 * @param {Token} token Lineage token.
 * @returns {boolean} True when no revision can follow.
 */
export function isFinalized(token: Token): boolean {
  try {
    BurnPredicate.fromPredicate(token.latestTransaction.recipient);
    return true;
  } catch {
    return false;
  }
}

/**
 * State mask of a version step, `x = PRF(k, h)`: derived from the producer's
 * private key and the state being spent rather than drawn at random. Re-running
 * an interrupted step with the same key, digest and recipient therefore rebuilds
 * the identical transaction, so a crash between certification and writing the
 * token file can be recovered by simply running the command again: the aggregator
 * already holds that exact request and its proof is fetched.
 *
 * @param {Uint8Array} privateKey Producer's secp256k1 private key.
 * @param {Token} token Token whose latest state is spent.
 * @returns {Promise<StateMask>} Deterministic state mask.
 */
export async function deriveStateMask(privateKey: Uint8Array, token: Token): Promise<StateMask> {
  const sourceStateHash = await token.latestTransaction.calculateStateHash();
  const hash = await new DataHasher(HashAlgorithm.SHA256)
    .update(
      CborSerializer.encodeArray(
        CborSerializer.encodeTextString(`${LINEAGE_TAG}/state-mask`),
        CborSerializer.encodeByteString(privateKey),
        CborSerializer.encodeByteString(sourceStateHash.imprint),
      ),
    )
    .digest();
  return StateMask.fromBytes(hash.data);
}

/**
 * Salt of a genesis, `salt = PRF(k_issuer, recipient, auxData)`: derived from the
 * issuer's private key, the encoded recipient and the revision 0 payload rather
 * than drawn at random. Re-running an interrupted genesis with the same key,
 * digest and recipient therefore rebuilds the identical mint, so the aggregator
 * returns the proof it already holds instead of a second, parallel lineage being
 * created. The token id `H(salt, network)` still cannot be computed by anyone
 * without the issuer's key, so nobody else can mint into its slot first.
 *
 * @param {Uint8Array} issuerPrivateKey Issuer's secp256k1 private key.
 * @param {EncodedPredicate} recipient Recipient predicate of the mint.
 * @param {Uint8Array} auxData Exact auxiliary data bytes of the mint.
 * @returns {Promise<TokenSalt>} Deterministic 32-byte salt.
 */
export async function deriveGenesisSalt(
  issuerPrivateKey: Uint8Array,
  recipient: EncodedPredicate,
  auxData: Uint8Array,
): Promise<TokenSalt> {
  const hash = await new DataHasher(HashAlgorithm.SHA256)
    .update(
      CborSerializer.encodeArray(
        CborSerializer.encodeTextString(`${LINEAGE_TAG}/salt`),
        CborSerializer.encodeByteString(issuerPrivateKey),
        recipient.toCBOR(),
        CborSerializer.encodeByteString(auxData),
      ),
    )
    .digest();
  return TokenSalt.fromBytes(hash.data);
}

/**
 * Payload and recipient of a revision: to the next producer's `P_sig`, or, when
 * there is none, sealed and burned, so that no further revision can follow.
 *
 * @param {bigint} index Revision index.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the revision.
 * @param {Uint8Array|null} nextProducer Next producer's public key; null to finalize.
 * @returns {Promise<{auxData: Uint8Array, recipient: SignaturePredicate | BurnPredicate}>} Payload bytes and recipient.
 */
async function revisionStep(
  index: bigint,
  digest: Uint8Array,
  nextProducer: Uint8Array | null,
): Promise<{ auxData: Uint8Array; recipient: SignaturePredicate | BurnPredicate }> {
  if (nextProducer === null) {
    const auxData = LineageRevision.create(index, digest, true).toCBOR();
    return { auxData, recipient: await sealPredicate(auxData) };
  }
  return {
    auxData: LineageRevision.create(index, digest).toCBOR(),
    recipient: SignaturePredicate.create(nextProducer),
  };
}

/**
 * Create a lineage: mint revision 0, with the issuer's signature as the mint
 * reason and the next producer's `P_sig` as recipient. The signature covers the
 * recipient, so the issuer names the producer of revision 1. Without a next producer
 * the lineage is finalized at once: revision 0 is a seal, minted to the burn
 * predicate.
 *
 * The salt is derived from the issuer's key ({@link deriveGenesisSalt}), so an
 * interrupted run recovers the same lineage when repeated, while the token id stays
 * unpredictable to everyone else and cannot be squatted. The token id is what
 * identifies the lineage; verifiers should receive it through a trusted channel.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the initial revision.
 * @param {Uint8Array} issuerPrivateKey Issuer's private key; signs the genesis reason.
 * @param {Uint8Array|null} nextProducer Compressed public key of whoever produces revision 1; null to finalize.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<Token>} Verified lineage token with no transfers.
 */
export async function createLineage(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  digest: Uint8Array,
  issuerPrivateKey: Uint8Array,
  nextProducer: Uint8Array | null,
  options: ICertifyOptions = {},
): Promise<Token> {
  return (await createOrRecoverLineage(client, trustBase, digest, issuerPrivateKey, nextProducer, options)).token;
}

/**
 * Build, without network contact, the genesis of a lineage. Deterministic in its
 * inputs: the salt is derived ({@link deriveGenesisSalt}) and the issuer's
 * signature is deterministic, so the same inputs always give the same mint.
 *
 * @param {RootTrustBase} trustBase Trust base of the network to mint on.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the initial revision.
 * @param {Uint8Array} issuerPrivateKey Issuer's private key; signs the genesis reason.
 * @param {Uint8Array|null} nextProducer Compressed public key of whoever produces revision 1; null to finalize.
 * @returns {Promise<MintTransaction>} The mint.
 */
export async function prepareLineage(
  trustBase: RootTrustBase,
  digest: Uint8Array,
  issuerPrivateKey: Uint8Array,
  nextProducer: Uint8Array | null,
): Promise<MintTransaction> {
  const { auxData, recipient } = await revisionStep(0n, digest, nextProducer);
  const encodedRecipient = EncodedPredicate.fromPredicate(recipient);
  const salt = await deriveGenesisSalt(issuerPrivateKey, encodedRecipient, auxData);
  const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
  const reason = await LineageGenesisReason.sign(
    tokenId,
    LINEAGE_TOKEN_TYPE,
    encodedRecipient,
    auxData,
    new SigningService(issuerPrivateKey),
  );
  return MintTransaction.create(trustBase.networkId, recipient, {
    data: auxData,
    justification: reason.toCBOR(),
    salt,
    tokenType: LINEAGE_TOKEN_TYPE,
  });
}

/** A genesis, and whether an earlier run had already certified it. */
export interface ILineageGenesis {
  /**
   * True when this genesis was certified before this call: by an interrupted run,
   * or by a run whose token file is elsewhere. The token is then revision 0 of an
   * existing lineage, which may have moved on since ({@link findSuccessor}).
   */
  readonly recovered: boolean;
  readonly token: Token;
}

/**
 * Create a lineage, or recover it if this genesis was already certified.
 *
 * The aggregator is asked first whether it holds this very mint; if so, nothing is
 * submitted. Otherwise the mint is submitted, and a `STATE_ID_EXISTS` answer for it
 * (an earlier request still waiting for its round when this one looked) counts as a
 * recovery too. A gateway that answers a repeat as a fresh success is caught by the
 * first check, unless the repeat comes within the earlier request's round.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the initial revision.
 * @param {Uint8Array} issuerPrivateKey Issuer's private key; signs the genesis reason.
 * @param {Uint8Array|null} nextProducer Compressed public key of whoever produces revision 1; null to finalize.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<ILineageGenesis>} Verified lineage token with no transfers, and whether it was recovered.
 */
export async function createOrRecoverLineage(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  digest: Uint8Array,
  issuerPrivateKey: Uint8Array,
  nextProducer: Uint8Array | null,
  options: ICertifyOptions = {},
): Promise<ILineageGenesis> {
  const transaction = await prepareLineage(trustBase, digest, issuerPrivateKey, nextProducer);
  const context = createLineageVerificationContext(trustBase);
  let recovered = false;
  let proof = await findCertifiedProof(client, context, transaction, options.signal);
  if (proof !== null) {
    recovered = true;
  } else {
    proof = await certifyTransaction(
      client,
      context,
      await CertificationData.fromMintTransaction(transaction),
      transaction,
      {
        ...options,
        onAlreadyCertified: (): void => {
          recovered = true;
          options.onAlreadyCertified?.();
        },
      },
    );
  }
  const certified = await transaction.toCertifiedTransaction(
    context.trustBase,
    context.predicateVerifier,
    context.unicityCertificateVerifier,
    proof,
  );
  return { recovered, token: await Token.mint(certified, context) };
}

/**
 * What the aggregator says about the state a token ends in: `spent`, with an
 * authenticated proof of the transfer that spent it; `unverified`, when it showed a
 * proof that does not verify; `none`, when it showed nothing. `none` is not proof
 * that no later revision exists: the aggregator issues no proofs of absence, and a
 * gateway can withhold one.
 */
export type SuccessorLookup =
  | { readonly kind: 'none' }
  | { readonly kind: 'spent'; readonly proof: InclusionProof }
  | { readonly kind: 'unverified' };

/**
 * Ask the aggregator whether the state the token ends in has been spent, that is,
 * whether the lineage has a revision after the token's latest one. Needs no key
 * and submits nothing: the next revision's state id depends only on the latest
 * state and the predicate locking it, both in the token. Its content cannot be
 * learned, since the aggregator holds only the transfer's hash.
 *
 * A proof is believed only once it verifies against the trust base: its path, the
 * consensus signatures over its round, and the signature of the key the latest
 * state is locked to, over the transfer it certifies.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Token} token Lineage token.
 * @param {AbortSignal} [signal] Abort signal for the request.
 * @returns {Promise<SuccessorLookup>} What the aggregator showed.
 */
export async function findSuccessor(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  signal?: AbortSignal,
): Promise<SuccessorLookup> {
  if (isFinalized(token)) {
    // Locked to a burn predicate, which nothing can unlock.
    return { kind: 'none' };
  }
  // The state id of any transfer out of the latest state; the probe's recipient
  // and mask do not enter it.
  const probe = await TransferTransaction.create(token, BurnPredicate.create(new Uint8Array(32)), StateMask.generate());
  let proof: InclusionProof | null;
  try {
    proof = (await client.getInclusionProof(await StateId.fromTransaction(probe), { signal })).inclusionProof;
  } catch (error) {
    if (error instanceof JsonRpcNetworkError && error.status === 404) {
      return { kind: 'none' };
    }
    throw error;
  }
  if (proof === null) {
    return { kind: 'none' };
  }
  const context = createLineageVerificationContext(trustBase);
  const result = await InclusionProofVerificationRule.verify(
    context.trustBase,
    context.predicateVerifier,
    context.unicityCertificateVerifier,
    proof,
    proof.certificationData.transactionHash,
    proof.certificationData.expiresAt,
    probe.lockScript,
    probe.sourceStateHash,
  );
  return result.status === InclusionProofVerificationStatus.OK ? { kind: 'spent', proof } : { kind: 'unverified' };
}

/**
 * Check, without network contact, that `token` is a valid lineage on the network of `trustBase`.
 *
 * @param {Token} token Lineage token.
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @throws {LineageError} `INVALID_TOKEN` if it does not verify.
 */
export async function assertValidLineage(token: Token, trustBase: RootTrustBase): Promise<void> {
  const result = await verifyLineage(token, trustBase);
  if (result.status !== 'OK') {
    throw new LineageError(
      `The token file is not a valid document lineage token: ${result.reason ?? 'unknown'}`,
      'INVALID_TOKEN',
    );
  }
}

/**
 * Check, without network contact, that `producerPrivateKey` can append to `token`
 * on the network of `trustBase`: the token is a valid lineage for that network and
 * its latest state is locked to that key's `P_sig`.
 *
 * @param {Token} token Existing lineage token.
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @param {Uint8Array} producerPublicKey Public key of the would-be producer.
 * @throws {LineageError} If the token is invalid or the key cannot unlock its latest state.
 */
export async function assertCanAppend(
  token: Token,
  trustBase: RootTrustBase,
  producerPublicKey: Uint8Array,
): Promise<void> {
  await assertValidLineage(token, trustBase);
  if (isFinalized(token)) {
    throw new LineageError('The lineage is finalized; no revision can follow its sealed final revision.', 'FINALIZED');
  }
  const current = currentProducerKey(token);
  if (current === null) {
    throw new LineageError(
      'The latest revision is not locked to a signature predicate; no key can append to this token.',
      'WRONG_KEY',
    );
  }
  if (!areUint8ArraysEqual(current, producerPublicKey)) {
    throw new LineageError(
      'The key does not match the producer named by the latest revision; only that key can append the next one.',
      'WRONG_KEY',
    );
  }
}

/** A revision ready to submit: the transfer and the request that certifies it. */
export interface IPreparedRevision {
  readonly certificationData: CertificationData;
  readonly index: bigint;
  readonly transaction: TransferTransaction;
}

/**
 * Build, without network contact, the next revision of `token`: a transfer, signed
 * under the `P_sig` the previous revision named, whose auxiliary data is
 * `[i, digest]` and whose recipient is the producer of revision `i + 1`; or,
 * without a next producer, the seal `["seal", i, digest]`, burning the token.
 * The state mask is derived, so the same inputs always give the same transfer.
 *
 * @param {Token} token Existing lineage token.
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the new revision.
 * @param {Uint8Array} producerPrivateKey Key named by the latest revision; signs the transfer.
 * @param {Uint8Array|null} nextProducer Compressed public key of whoever produces the following revision; null to finalize.
 * @returns {Promise<IPreparedRevision>} The transfer, its index and its certification request.
 * @throws {LineageError} If the token is invalid or the key cannot append to it.
 */
export async function prepareRevision(
  token: Token,
  trustBase: RootTrustBase,
  digest: Uint8Array,
  producerPrivateKey: Uint8Array,
  nextProducer: Uint8Array | null,
): Promise<IPreparedRevision> {
  const signer = new SigningService(producerPrivateKey);
  await assertCanAppend(token, trustBase, signer.publicKey);

  const index = nextRevisionIndex(token);
  const { auxData, recipient } = await revisionStep(index, digest, nextProducer);
  const transaction = await TransferTransaction.create(
    token,
    recipient,
    await deriveStateMask(producerPrivateKey, token),
    { data: auxData },
  );
  const certificationData = await CertificationData.fromTransaction(
    transaction,
    await SignaturePredicateUnlockScript.create(transaction, signer),
  );
  return { certificationData, index, transaction };
}

/**
 * @param {Token} token Lineage token.
 * @returns {bigint} Index of the revision that would be appended next.
 */
export function nextRevisionIndex(token: Token): bigint {
  return BigInt(token.transactions.length + 1);
}

/**
 * Whether `transaction` is the revision that `digest` and `nextProducer` would
 * make at its position. Needs no key: it compares what the transfer carries.
 *
 * @param {TransferTransaction} transaction A lineage transfer.
 * @param {bigint} index Its revision index.
 * @param {Uint8Array} digest 32-byte SHA-256 digest.
 * @param {Uint8Array|null} nextProducer Next producer's public key; null for a seal.
 * @returns {Promise<boolean>} True when payload and recipient both match.
 */
export async function isSameRevision(
  transaction: TransferTransaction,
  index: bigint,
  digest: Uint8Array,
  nextProducer: Uint8Array | null,
): Promise<boolean> {
  const { auxData, recipient } = await revisionStep(index, digest, nextProducer);
  const data = transaction.data;
  return (
    data !== null &&
    areUint8ArraysEqual(data, auxData) &&
    areUint8ArraysEqual(transaction.recipient.toCBOR(), EncodedPredicate.fromPredicate(recipient).toCBOR())
  );
}

function alreadyCertified(index: bigint, cause: unknown): LineageError {
  return new LineageError(
    `Revision ${index} of this lineage was already certified with different content, probably by an earlier ` +
      "interrupted run whose token file was not written. Run stamp-revision again with that run's digest and " +
      'next producer to recover it.',
    'ALREADY_CERTIFIED',
    { cause },
  );
}

/**
 * Attach a certified transfer to the token and check it against the chain rules.
 *
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @param {Token} token Lineage token the transfer continues.
 * @param {TransferTransaction} transaction The transfer.
 * @param {InclusionProof} proof Its inclusion proof.
 * @param {ICertifyOptions} options Warning sink.
 * @returns {Promise<Token>} The token with the transfer appended.
 */
async function attachRevision(
  trustBase: RootTrustBase,
  token: Token,
  transaction: TransferTransaction,
  proof: InclusionProof,
  options: ICertifyOptions,
): Promise<Token> {
  const context = createLineageVerificationContext(trustBase);
  const certified = await transaction.toCertifiedTransaction(
    context.trustBase,
    context.predicateVerifier,
    context.unicityCertificateVerifier,
    proof,
  );
  const appended = await token.transfer(certified, context);

  // The SDK checks the new transfer on its own; the chain rules relate it to its
  // predecessor. It is certified either way, so a violation is reported, not thrown.
  const check = await verifyLineage(appended, trustBase);
  if (check.status !== 'OK') {
    options.onWarning?.(`The appended revision breaks a lineage rule: ${check.reason ?? 'unknown'}`);
  }
  return appended;
}

/**
 * Submit a prepared revision and append it to the token once certified. A repeat
 * of an already certified revision recovers it.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Token} token The token the revision was prepared for.
 * @param {IPreparedRevision} prepared From {@link prepareRevision}.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<Token>} The token with the new revision appended.
 * @throws {LineageError} `ALREADY_CERTIFIED` if this revision slot holds another transfer.
 */
export async function certifyRevision(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  prepared: IPreparedRevision,
  options: ICertifyOptions = {},
): Promise<Token> {
  const context = createLineageVerificationContext(trustBase);
  let proof: InclusionProof;
  try {
    proof = await certifyTransaction(client, context, prepared.certificationData, prepared.transaction, options);
  } catch (error) {
    if (error instanceof StateAlreadyCertifiedError) {
      throw alreadyCertified(prepared.index, error);
    }
    throw error;
  }
  return attachRevision(trustBase, token, prepared.transaction, proof, options);
}

/**
 * Recover a revision that an earlier run submitted but did not record: if the
 * aggregator certified `transaction`, append it to the token. Needs no key, and
 * submits nothing.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Token} token The token the transfer continues.
 * @param {TransferTransaction} transaction The transfer the earlier run submitted.
 * @param {ICertifyOptions} options Abort signal, warning sink.
 * @returns {Promise<Token|null>} The token with the revision appended, or null if it is not certified.
 * @throws {LineageError} `ALREADY_CERTIFIED` if the slot holds another transfer instead.
 */
export async function recoverRevision(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  transaction: TransferTransaction,
  options: ICertifyOptions = {},
): Promise<Token | null> {
  let proof: InclusionProof | null;
  try {
    proof = await findCertifiedProof(client, createLineageVerificationContext(trustBase), transaction, options.signal);
  } catch (error) {
    if (error instanceof StateAlreadyCertifiedError) {
      throw alreadyCertified(nextRevisionIndex(token), error);
    }
    throw error;
  }
  return proof === null ? null : attachRevision(trustBase, token, transaction, proof, options);
}

/**
 * Append the next revision: {@link prepareRevision}, then {@link certifyRevision}.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Token} token Existing lineage token.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the new revision.
 * @param {Uint8Array} producerPrivateKey Key named by the latest revision; signs the transfer.
 * @param {Uint8Array|null} nextProducer Compressed public key of whoever produces the following revision; null to finalize.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<Token>} The token with the new revision appended.
 */
export async function appendRevision(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  digest: Uint8Array,
  producerPrivateKey: Uint8Array,
  nextProducer: Uint8Array | null,
  options: ICertifyOptions = {},
): Promise<Token> {
  const prepared = await prepareRevision(token, trustBase, digest, producerPrivateKey, nextProducer);
  return certifyRevision(client, trustBase, token, prepared, options);
}
