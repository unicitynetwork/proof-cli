import { DataHash } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHash.js';
import { DataHasher } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/DataHasher.js';
import { HashAlgorithm } from '@unicitylabs/state-transition-sdk/lib/crypto/hash/HashAlgorithm.js';
import { Signature } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/Signature.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { CborDeserializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborDeserializer.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';

/**
 * The seed string of the document lineage format: the token type is its SHA-256,
 * and it is the domain tag of every signature and derivation the format defines.
 * Like `unicity-timestamp`, it must never change once tokens exist.
 */
export const LINEAGE_TAG = 'unicity-document-lineage';

/** SHA-256 of {@link LINEAGE_TAG}. Pinned here; a unit test asserts the derivation. */
export const LINEAGE_TOKEN_TYPE_HEX = '962e2defb924f7a9a92fee6a7eabab658933fd3973117fc5ed70587474f37028';

/** Token type `DOC_LINEAGE` shared by every document lineage token. */
export const LINEAGE_TOKEN_TYPE: TokenType = new TokenType(HexConverter.decode(LINEAGE_TOKEN_TYPE_HEX));

/**
 * CBOR tag of the genesis mint reason. The SDK dispatches mint justifications by
 * tag, so the reason must carry one. Chosen outside the 39000–39099 block the SDK
 * and the Yellowpaper use for their own structures.
 */
export const LINEAGE_GENESIS_REASON_TAG = 39200n;

/** First element of the genesis reason array. */
export const LINEAGE_REASON_VERSION = 1n;

const DIGEST_LENGTH = 32;
const PUBLIC_KEY_LENGTH = 33;
const SIGNATURE_LENGTH = 65;

/** Thrown when bytes do not form a valid lineage structure. */
export class LineageFormatError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LineageFormatError';
  }
}

function assertDigest(digest: Uint8Array): void {
  if (digest.length !== DIGEST_LENGTH) {
    throw new LineageFormatError(`Digest must be ${DIGEST_LENGTH} bytes (SHA-256), got ${digest.length} bytes.`);
  }
}

/**
 * Deterministic CBOR only: what was decoded must re-encode to exactly the input,
 * which rejects trailing bytes and non-minimal encodings in one comparison.
 */
function assertCanonical(input: Uint8Array, reencoded: Uint8Array, what: string): void {
  if (!areUint8ArraysEqual(input, reencoded)) {
    throw new LineageFormatError(`${what} is not in canonical CBOR encoding.`);
  }
}

/** First element of a seal payload, marking the revision as final. */
export const LINEAGE_SEAL_MARKER = 'seal';

/**
 * Auxiliary data of every lineage transaction: the revision index (0 at genesis,
 * then one more per transfer) and the SHA-256 digest of that revision. The
 * document itself is never stored. No previous digest is needed; linkage comes
 * from the state hash chain.
 *
 * ```
 * CBOR[i, H(doc_i)]            an ordinary revision
 * CBOR["seal", i, H(doc_i)]    the final revision (seal)
 * ```
 *
 * A seal is certified with the burn predicate `P_burn(H(b_seal))` as recipient,
 * where `b_seal` is the seal payload itself, so no successor can ever exist and
 * the burn commits to the final digest.
 */
export class LineageRevision {
  private constructor(
    public readonly index: bigint,
    private readonly _digest: Uint8Array,
    /** Whether this is the final revision, after which the token is burned. */
    public readonly sealed: boolean,
  ) {
    this._digest = new Uint8Array(_digest);
  }

  /** @returns {Uint8Array} Copy of the 32-byte SHA-256 digest of the revision. */
  public get digest(): Uint8Array {
    return new Uint8Array(this._digest);
  }

  /**
   * @param {bigint} index Revision index.
   * @param {Uint8Array} digest 32-byte SHA-256 digest.
   * @param {boolean} sealed Whether this is the final revision.
   * @returns {LineageRevision} Revision payload.
   * @throws {LineageFormatError} If the digest is not 32 bytes or the index is negative.
   */
  public static create(index: bigint, digest: Uint8Array, sealed = false): LineageRevision {
    if (index < 0n) {
      throw new LineageFormatError(`Revision index must not be negative, got ${index}.`);
    }
    assertDigest(digest);
    return new LineageRevision(index, digest, sealed);
  }

  /**
   * Strict decoder.
   *
   * @param {Uint8Array} bytes CBOR bytes.
   * @returns {LineageRevision} Decoded payload.
   * @throws {LineageFormatError} On any structural problem.
   */
  public static fromCBOR(bytes: Uint8Array): LineageRevision {
    let index: bigint;
    let digest: Uint8Array;
    let sealed: boolean;
    try {
      const elements = CborDeserializer.decodeArray(bytes);
      if (elements.length === 2) {
        sealed = false;
      } else if (elements.length === 3 && CborDeserializer.decodeTextString(elements[0]) === LINEAGE_SEAL_MARKER) {
        sealed = true;
        elements.shift();
      } else {
        throw new LineageFormatError('Unexpected revision payload shape.');
      }
      index = CborDeserializer.decodeUnsignedInteger(elements[0]);
      digest = CborDeserializer.decodeByteString(elements[1]);
    } catch (error) {
      throw new LineageFormatError(
        `Revision payload is not a CBOR array of [index, digest] or ["${LINEAGE_SEAL_MARKER}", index, digest].`,
        { cause: error },
      );
    }
    assertDigest(digest);
    const revision = new LineageRevision(index, digest, sealed);
    assertCanonical(bytes, revision.toCBOR(), 'Revision payload');
    return revision;
  }

  /** @returns {Uint8Array} CBOR encoding. */
  public toCBOR(): Uint8Array {
    const fields = [CborSerializer.encodeUnsignedInteger(this.index), CborSerializer.encodeByteString(this._digest)];
    return this.sealed
      ? CborSerializer.encodeArray(CborSerializer.encodeTextString(LINEAGE_SEAL_MARKER), ...fields)
      : CborSerializer.encodeArray(...fields);
  }
}

/**
 * The predicate a sealed revision is certified to: `P_burn(H(b_seal))`, with the
 * SHA-256 of the exact seal payload bytes as the burn reason.
 *
 * @param {Uint8Array} sealPayload CBOR of the sealed {@link LineageRevision}.
 * @returns {Promise<BurnPredicate>} The burn predicate.
 */
export async function sealPredicate(sealPayload: Uint8Array): Promise<BurnPredicate> {
  const hash = await new DataHasher(HashAlgorithm.SHA256).update(sealPayload).digest();
  return BurnPredicate.create(hash.data);
}

/**
 * Genesis mint reason: the issuer's signature over `(id, ty, auxData)`.
 *
 * ```
 * tag 39200 [ 1, issuer(33), signature(65) ]
 * ```
 *
 * The mint key is public, so anyone can mint a token of any type; this signature
 * is what makes an origin "accepted". Verifiers pin a lineage by its token id, or
 * by the issuer key together with the initial digest.
 */
export class LineageGenesisReason {
  private constructor(
    private readonly _issuer: Uint8Array,
    public readonly signature: Signature,
  ) {
    this._issuer = new Uint8Array(_issuer);
  }

  /** @returns {Uint8Array} Copy of the issuer's compressed public key. */
  public get issuer(): Uint8Array {
    return new Uint8Array(this._issuer);
  }

  /**
   * Strict decoder.
   *
   * @param {Uint8Array} bytes CBOR bytes.
   * @returns {LineageGenesisReason} Decoded reason.
   * @throws {LineageFormatError} On any structural problem.
   */
  public static fromCBOR(bytes: Uint8Array): LineageGenesisReason {
    let version: bigint;
    let issuer: Uint8Array;
    let signatureBytes: Uint8Array;
    try {
      const tag = CborDeserializer.decodeTag(bytes);
      if (tag.tag !== LINEAGE_GENESIS_REASON_TAG) {
        throw new LineageFormatError(`Unexpected CBOR tag ${tag.tag}.`);
      }
      const elements = CborDeserializer.decodeArray(tag.data, 3);
      version = CborDeserializer.decodeUnsignedInteger(elements[0]);
      issuer = CborDeserializer.decodeByteString(elements[1]);
      signatureBytes = CborDeserializer.decodeByteString(elements[2]);
    } catch (error) {
      throw new LineageFormatError(
        `Genesis reason is not tag ${LINEAGE_GENESIS_REASON_TAG} over [version, issuer, signature].`,
        { cause: error },
      );
    }
    if (version !== LINEAGE_REASON_VERSION) {
      throw new LineageFormatError(
        `Unsupported genesis reason version ${version}; expected ${LINEAGE_REASON_VERSION}.`,
      );
    }
    if (issuer.length !== PUBLIC_KEY_LENGTH || !SigningService.isPublicKeyValid(issuer)) {
      throw new LineageFormatError('Issuer is not a valid compressed secp256k1 public key.');
    }
    if (signatureBytes.length !== SIGNATURE_LENGTH) {
      throw new LineageFormatError(`Signature must be ${SIGNATURE_LENGTH} bytes, got ${signatureBytes.length} bytes.`);
    }
    let signature: Signature;
    try {
      signature = Signature.decode(signatureBytes);
    } catch (error) {
      throw new LineageFormatError('Signature is malformed.', { cause: error });
    }
    const reason = new LineageGenesisReason(issuer, signature);
    assertCanonical(bytes, reason.toCBOR(), 'Genesis reason');
    return reason;
  }

  /**
   * @param {TokenId} tokenId Token id of the lineage.
   * @param {TokenType} tokenType Token type.
   * @param {Uint8Array} auxData Exact auxiliary data bytes of the mint.
   * @param {SigningService} issuer Issuer's signing service.
   * @returns {Promise<LineageGenesisReason>} Signed reason.
   */
  public static async sign(
    tokenId: TokenId,
    tokenType: TokenType,
    auxData: Uint8Array,
    issuer: SigningService,
  ): Promise<LineageGenesisReason> {
    const signature = await issuer.sign(await LineageGenesisReason.signedMessage(tokenId, tokenType, auxData));
    return new LineageGenesisReason(issuer.publicKey, signature);
  }

  /**
   * Message the issuer signs:
   * `SHA-256(CBOR["unicity-document-lineage", 1, id, ty, auxData])`.
   *
   * @param {TokenId} tokenId Token id of the lineage.
   * @param {TokenType} tokenType Token type.
   * @param {Uint8Array} auxData Exact auxiliary data bytes of the mint.
   * @returns {Promise<DataHash>} Message hash.
   */
  public static signedMessage(tokenId: TokenId, tokenType: TokenType, auxData: Uint8Array): Promise<DataHash> {
    return new DataHasher(HashAlgorithm.SHA256)
      .update(
        CborSerializer.encodeArray(
          CborSerializer.encodeTextString(LINEAGE_TAG),
          CborSerializer.encodeUnsignedInteger(LINEAGE_REASON_VERSION),
          CborSerializer.encodeByteString(tokenId.bytes),
          CborSerializer.encodeByteString(tokenType.bytes),
          CborSerializer.encodeByteString(auxData),
        ),
      )
      .digest();
  }

  /** @returns {Uint8Array} Tagged CBOR encoding. */
  public toCBOR(): Uint8Array {
    return CborSerializer.encodeTag(
      LINEAGE_GENESIS_REASON_TAG,
      CborSerializer.encodeArray(
        CborSerializer.encodeUnsignedInteger(LINEAGE_REASON_VERSION),
        CborSerializer.encodeByteString(this._issuer),
        CborSerializer.encodeByteString(this.signature.encode()),
      ),
    );
  }

  /**
   * @param {TokenId} tokenId Token id of the lineage.
   * @param {TokenType} tokenType Token type.
   * @param {Uint8Array} auxData Exact auxiliary data bytes of the mint.
   * @returns {Promise<boolean>} True if the signature verifies for the issuer.
   */
  public async verify(tokenId: TokenId, tokenType: TokenType, auxData: Uint8Array): Promise<boolean> {
    return SigningService.verifyWithPublicKey(
      await LineageGenesisReason.signedMessage(tokenId, tokenType, auxData),
      this.signature,
      this._issuer,
    );
  }
}
