import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

/**
 * The one seed string of the format. The token type is its SHA-256, the burn
 * reason is its UTF-8 bytes, and it is the domain tag of the payload signature.
 * It carries no version on purpose: the payload has its own version field, so
 * this identifier stays stable while the payload format evolves.
 *
 * It is also not the product name, and must never be changed to match it.
 * Renaming it gives every later stamp a different token type, recipient and
 * signature domain, and nothing already certified would verify. The CLI is
 * `unicity-proof`; the format is `unicity-timestamp` and stays so.
 */
export const TIMESTAMP_TAG = 'unicity-timestamp';

/** First element of the payload array. Version 1 means a 32-byte SHA-256 digest. */
export const PAYLOAD_VERSION = 1n;

/** SHA-256 of {@link TIMESTAMP_TAG}. Pinned here; a unit test asserts the derivation. */
export const TIMESTAMP_TOKEN_TYPE_HEX = 'dd671898ac55e0a3a9e22f07120cef94943d25fdf1dd0485aab077b21ee16193';

/** Token type shared by every timestamp token. The issuance verifier is registered for exactly this type. */
export const TIMESTAMP_TOKEN_TYPE: TokenType = new TokenType(HexConverter.decode(TIMESTAMP_TOKEN_TYPE_HEX));

/** Reason bytes of the burn predicate every timestamp token is locked to. */
export const TIMESTAMP_BURN_REASON: Uint8Array = new TextEncoder().encode(TIMESTAMP_TAG);

/**
 * Recipient of every timestamp token. A burn predicate has no verifier in the
 * SDK, so the state can never be spent: the token is not transferable and
 * belongs to nobody. Identity, when present, lives in the payload instead.
 */
export const TIMESTAMP_RECIPIENT: BurnPredicate = BurnPredicate.create(TIMESTAMP_BURN_REASON);

/** Encoded form of {@link TIMESTAMP_RECIPIENT}, compared against a token's genesis recipient. */
export const TIMESTAMP_RECIPIENT_ENCODED: EncodedPredicate = EncodedPredicate.fromPredicate(TIMESTAMP_RECIPIENT);
