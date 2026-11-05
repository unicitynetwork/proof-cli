import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { CertificationData } from '@unicitylabs/state-transition-sdk/lib/api/CertificationData.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { SignaturePredicateUnlockScript } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicateUnlockScript.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { MintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/MintTransaction.js';
import { StateMask } from '@unicitylabs/state-transition-sdk/lib/transaction/StateMask.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';

import { LINEAGE_TAG, LINEAGE_TOKEN_TYPE, LineageGenesisReason, LineageRevision } from './LineagePayload.js';
import { createLineageVerificationContext, verifyLineage } from './LineageVerification.js';
import { ICertifyOptions, certifyMintTransaction, certifyTransaction } from '../TimestampClient.js';

/** Thrown when a revision cannot be appended to the given token with the given key. */
export class LineageError extends Error {
  public constructor(
    message: string,
    /** `INVALID_TOKEN`: the token does not verify as a lineage; `WRONG_KEY`: the key cannot append to it. */
    public readonly code: 'INVALID_TOKEN' | 'WRONG_KEY',
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
 * Create a lineage: mint revision 0, with the issuer's signature as the mint
 * reason and the next producer's `P_sig` as recipient.
 *
 * The salt is random, so the token id stays unpredictable until the genesis is
 * certified and cannot be squatted.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the initial revision.
 * @param {Uint8Array} issuerPrivateKey Issuer's private key; signs the genesis reason.
 * @param {Uint8Array} nextProducer Compressed public key of whoever produces revision 1.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<Token>} Verified lineage token with no transfers.
 */
export async function createLineage(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  digest: Uint8Array,
  issuerPrivateKey: Uint8Array,
  nextProducer: Uint8Array,
  options: ICertifyOptions = {},
): Promise<Token> {
  const recipient = SignaturePredicate.create(nextProducer);
  const auxData = LineageRevision.create(0n, digest).toCBOR();
  const salt = TokenSalt.generate();
  const tokenId = await TokenId.fromSalt(trustBase.networkId, salt);
  const reason = await LineageGenesisReason.sign(
    tokenId,
    LINEAGE_TOKEN_TYPE,
    auxData,
    new SigningService(issuerPrivateKey),
  );
  const transaction = await MintTransaction.create(trustBase.networkId, recipient, {
    data: auxData,
    justification: reason.toCBOR(),
    salt,
    tokenType: LINEAGE_TOKEN_TYPE,
  });
  const context = createLineageVerificationContext(trustBase);
  return Token.mint(await certifyMintTransaction(client, context, transaction, options), context);
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
  const result = await verifyLineage(token, trustBase);
  if (result.status !== 'OK') {
    throw new LineageError(
      `The token file is not a valid document lineage token: ${result.reason ?? 'unknown'}`,
      'INVALID_TOKEN',
    );
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

/**
 * Append the next revision: a transfer, signed under the `P_sig` the previous
 * revision named, whose auxiliary data is `[i, digest]` and whose recipient is the
 * producer of revision `i + 1`.
 *
 * @param {StateTransitionClient} client Aggregator client.
 * @param {RootTrustBase} trustBase Trust base of the network behind the client.
 * @param {Token} token Existing lineage token.
 * @param {Uint8Array} digest 32-byte SHA-256 digest of the new revision.
 * @param {Uint8Array} producerPrivateKey Key named by the latest revision; signs the transfer.
 * @param {Uint8Array} nextProducer Compressed public key of whoever produces the following revision.
 * @param {ICertifyOptions} options Timeout, poll interval, abort signal, warning sink.
 * @returns {Promise<Token>} The token with the new revision appended.
 */
export async function appendRevision(
  client: StateTransitionClient,
  trustBase: RootTrustBase,
  token: Token,
  digest: Uint8Array,
  producerPrivateKey: Uint8Array,
  nextProducer: Uint8Array,
  options: ICertifyOptions = {},
): Promise<Token> {
  const signer = new SigningService(producerPrivateKey);
  await assertCanAppend(token, trustBase, signer.publicKey);

  const recipient = SignaturePredicate.create(nextProducer);
  const index = BigInt(token.transactions.length + 1);
  const transaction = await TransferTransaction.create(
    token,
    recipient,
    await deriveStateMask(producerPrivateKey, token),
    { data: LineageRevision.create(index, digest).toCBOR() },
  );
  const certificationData = await CertificationData.fromTransaction(
    transaction,
    await SignaturePredicateUnlockScript.create(transaction, signer),
  );
  const context = createLineageVerificationContext(trustBase);
  const proof = await certifyTransaction(client, context, certificationData, transaction, options);
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
