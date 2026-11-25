import { createHash } from 'node:crypto';

import { NetworkId } from '@unicitylabs/state-transition-sdk/lib/api/NetworkId.js';
import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { BurnPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/BurnPredicate.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { CborSerializer } from '@unicitylabs/state-transition-sdk/lib/serialization/cbor/CborSerializer.js';
import { TokenId } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenId.js';
import { TokenSalt } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenSalt.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import {
  LINEAGE_TAG,
  LINEAGE_TOKEN_TYPE,
  LINEAGE_TOKEN_TYPE_HEX,
  LineageFormatError,
  LineageGenesisReason,
  LineageRevision,
  sealPredicate,
} from '../../../src/lib/LineagePayload.js';
import { OTHER_DIGEST, TEST_DIGEST } from '../../support/fixtures.js';

describe('LineagePayload', () => {
  const alice = SigningService.generatePrivateKey();
  const publicKey = (key: Uint8Array): Uint8Array => new SigningService(key).publicKey;

  it('pins the token type to SHA-256 of the tag', () => {
    expect(createHash('sha256').update(LINEAGE_TAG).digest('hex')).toEqual(LINEAGE_TOKEN_TYPE_HEX);
  });

  describe('LineageRevision', () => {
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
  });

  describe('sealPredicate', () => {
    it('burns with the SHA-256 of the seal payload as reason', async () => {
      const payload = LineageRevision.create(2n, TEST_DIGEST, true).toCBOR();
      const predicate = EncodedPredicate.fromPredicate(await sealPredicate(payload));
      expect(BurnPredicate.fromPredicate(predicate).reason).toEqual(
        new Uint8Array(createHash('sha256').update(payload).digest()),
      );
    });
  });

  describe('LineageGenesisReason', () => {
    const bob = EncodedPredicate.fromPredicate(
      SignaturePredicate.create(publicKey(SigningService.generatePrivateKey())),
    );
    const carol = EncodedPredicate.fromPredicate(
      SignaturePredicate.create(publicKey(SigningService.generatePrivateKey())),
    );

    it('round-trips a genesis reason and rejects a wrong tag', async () => {
      const tokenId = await TokenId.fromSalt(NetworkId.LOCAL, TokenSalt.generate());
      const reason = await LineageGenesisReason.sign(
        tokenId,
        LINEAGE_TOKEN_TYPE,
        bob,
        TEST_DIGEST,
        new SigningService(alice),
      );
      const decoded = LineageGenesisReason.fromCBOR(reason.toCBOR());
      expect(decoded.issuer).toEqual(publicKey(alice));
      expect(await decoded.verify(tokenId, LINEAGE_TOKEN_TYPE, bob, TEST_DIGEST)).toBe(true);
      expect(await decoded.verify(tokenId, LINEAGE_TOKEN_TYPE, bob, OTHER_DIGEST)).toBe(false);

      const wrongTag = CborSerializer.encodeTag(1n, CborSerializer.encodeArray());
      expect(() => LineageGenesisReason.fromCBOR(wrongTag)).toThrow(LineageFormatError);
    });

    it('signs the recipient: the signature holds for no other first producer', async () => {
      const tokenId = await TokenId.fromSalt(NetworkId.LOCAL, TokenSalt.generate());
      const reason = await LineageGenesisReason.sign(
        tokenId,
        LINEAGE_TOKEN_TYPE,
        bob,
        TEST_DIGEST,
        new SigningService(alice),
      );
      expect(await reason.verify(tokenId, LINEAGE_TOKEN_TYPE, bob, TEST_DIGEST)).toBe(true);
      expect(await reason.verify(tokenId, LINEAGE_TOKEN_TYPE, carol, TEST_DIGEST)).toBe(false);
      const burn = EncodedPredicate.fromPredicate(await sealPredicate(TEST_DIGEST));
      expect(await reason.verify(tokenId, LINEAGE_TOKEN_TYPE, burn, TEST_DIGEST)).toBe(false);
    });

    it('pins the signed message format', async () => {
      const tokenId = await TokenId.fromSalt(NetworkId.LOCAL, TokenSalt.generate());
      const message = await LineageGenesisReason.signedMessage(tokenId, LINEAGE_TOKEN_TYPE, bob, TEST_DIGEST);
      const expected = createHash('sha256')
        .update(
          CborSerializer.encodeArray(
            CborSerializer.encodeTextString(LINEAGE_TAG),
            CborSerializer.encodeUnsignedInteger(1n),
            CborSerializer.encodeByteString(tokenId.bytes),
            CborSerializer.encodeByteString(LINEAGE_TOKEN_TYPE.bytes),
            bob.toCBOR(),
            CborSerializer.encodeByteString(TEST_DIGEST),
          ),
        )
        .digest();
      expect(message.data).toEqual(new Uint8Array(expected));
    });
  });

  it('builds the recipient as a P_sig predicate', () => {
    const predicate = EncodedPredicate.fromPredicate(SignaturePredicate.create(publicKey(alice)));
    expect(SignaturePredicate.fromPredicate(predicate).publicKey).toEqual(publicKey(alice));
  });
});
