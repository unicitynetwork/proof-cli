import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';
import { SignaturePredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/builtin/SignaturePredicate.js';
import { EncodedPredicate } from '@unicitylabs/state-transition-sdk/lib/predicate/EncodedPredicate.js';
import { PredicateVerifierService } from '@unicitylabs/state-transition-sdk/lib/predicate/verification/PredicateVerifierService.js';
import { CertifiedMintTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/CertifiedMintTransaction.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TokenType } from '@unicitylabs/state-transition-sdk/lib/transaction/TokenType.js';
import type { IMintJustificationVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/IMintJustificationVerifier.js';
import type { ITokenIssuanceVerifier } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/ITokenIssuanceVerifier.js';
import { MintJustificationVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/MintJustificationVerifierService.js';
import { TokenIssuanceVerifierService } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/TokenIssuanceVerifierService.js';
import { VerificationContext } from '@unicitylabs/state-transition-sdk/lib/transaction/verification/VerificationContext.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';
import { VerificationStatus } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationStatus.js';

import {
  LINEAGE_GENESIS_REASON_TAG,
  LINEAGE_TOKEN_TYPE,
  LineageGenesisReason,
  LineageRevision,
} from './LineagePayload.js';
import { errorMessage } from '../errors.js';
import { createUnicityCertificateVerifier } from '../verification.js';

type Result = VerificationResult<VerificationStatus>;

function check(rule: string, ok: boolean, failureMessage: string): Result {
  return new VerificationResult(rule, ok ? VerificationStatus.OK : VerificationStatus.FAIL, ok ? '' : failureMessage);
}

function combine(rule: string, results: Result[]): Result {
  const firstFailure = results.find((result) => result.status !== VerificationStatus.OK);
  return VerificationResult.fromResults(rule, results, firstFailure?.message ?? '');
}

/**
 * Issuance policy for `DOC_LINEAGE` tokens: the genesis carries revision 0 as its
 * auxiliary data and an issuer reason. The reason's signature is checked by
 * {@link LineageGenesisReasonVerifier}, which the SDK dispatches by CBOR tag; this
 * verifier only insists the reason is there, because the SDK accepts a mint with
 * no justification at all. The recipient may be any predicate.
 */
export class LineageIssuanceVerifier implements ITokenIssuanceVerifier {
  public static readonly RULE = 'LineageIssuanceVerification';

  /** @returns {TokenType} The document lineage token type. */
  public get tokenType(): TokenType {
    return LINEAGE_TOKEN_TYPE;
  }

  /** @inheritDoc */
  public verify(transaction: CertifiedMintTransaction): Promise<Result> {
    const results: Result[] = [];
    try {
      results.push(
        check('GenesisReasonPresent', transaction.justification !== null, 'Lineage genesis carries no issuer reason.'),
      );
      const data = transaction.data;
      if (data === null) {
        results.push(check('RevisionPresent', false, 'Lineage genesis carries no revision payload.'));
      } else {
        const revision = LineageRevision.fromCBOR(data);
        results.push(check('RevisionDecodes', true, ''));
        results.push(
          check('GenesisRevisionIsZero', revision.index === 0n, `Genesis revision index is ${revision.index}, not 0.`),
        );
      }
    } catch (error) {
      results.push(check('RevisionDecodes', false, errorMessage(error)));
    }
    return Promise.resolve(combine(LineageIssuanceVerifier.RULE, results));
  }
}

/** Checks the issuer signature in a lineage genesis reason. */
export class LineageGenesisReasonVerifier implements IMintJustificationVerifier {
  public static readonly RULE = 'LineageGenesisReasonVerification';

  /** @returns {bigint} CBOR tag of the lineage genesis reason. */
  public get tag(): bigint {
    return LINEAGE_GENESIS_REASON_TAG;
  }

  /** @inheritDoc */
  public async verify(transaction: CertifiedMintTransaction): Promise<Result> {
    const results: Result[] = [];
    try {
      if (!areUint8ArraysEqual(transaction.tokenType.bytes, LINEAGE_TOKEN_TYPE.bytes)) {
        results.push(check('TokenTypeIsLineage', false, 'A lineage genesis reason on a token of another type.'));
      } else {
        const reason = LineageGenesisReason.fromCBOR(transaction.justification as Uint8Array);
        const data = transaction.data ?? new Uint8Array();
        results.push(
          check(
            'IssuerSignatureValid',
            await reason.verify(transaction.tokenId, transaction.tokenType, data),
            'Issuer signature in the genesis reason does not verify.',
          ),
        );
      }
    } catch (error) {
      results.push(check('GenesisReasonDecodes', false, errorMessage(error)));
    }
    return combine(LineageGenesisReasonVerifier.RULE, results);
  }
}

/**
 * Verification context that accepts document lineage tokens and nothing else.
 *
 * @param {RootTrustBase} trustBase Trust base of the network the token belongs to.
 * @returns {VerificationContext} Context for `token.verify`, `Token.mint` and `token.transfer`.
 */
export function createLineageVerificationContext(trustBase: RootTrustBase): VerificationContext {
  return new VerificationContext(
    trustBase,
    PredicateVerifierService.create(),
    createUnicityCertificateVerifier(),
    new MintJustificationVerifierService().register(new LineageGenesisReasonVerifier()),
    new TokenIssuanceVerifierService(true).register(new LineageIssuanceVerifier()),
  );
}

/** One revision of a lineage as read off the token. */
export interface ILineageRevisionDescription {
  readonly digest: Uint8Array | null;
  readonly error: string | null;
  readonly index: bigint | null;
  /** Public key of the `P_sig` the revision names as producer of the next one; null for any other predicate. */
  readonly nextProducer: Uint8Array | null;
  /** Unix seconds. */
  readonly referenceTime: bigint;
}

/** What a lineage token claims, without verifying it. */
export interface ILineageDescription {
  readonly issuer: Uint8Array | null;
  readonly revisions: readonly ILineageRevisionDescription[];
  readonly token: Token;
  readonly tokenTypeIsLineage: boolean;
}

function signaturePredicateKey(predicate: EncodedPredicate): Uint8Array | null {
  try {
    return SignaturePredicate.fromPredicate(predicate).publicKey;
  } catch {
    return null;
  }
}

function describeRevision(
  data: Uint8Array | null,
  recipient: EncodedPredicate,
  referenceTime: bigint,
): ILineageRevisionDescription {
  const nextProducer = signaturePredicateKey(recipient);
  if (data === null) {
    return { digest: null, error: 'no revision payload', index: null, nextProducer, referenceTime };
  }
  try {
    const revision = LineageRevision.fromCBOR(data);
    return { digest: revision.digest, error: null, index: revision.index, nextProducer, referenceTime };
  } catch (error) {
    return { digest: null, error: errorMessage(error), index: null, nextProducer, referenceTime };
  }
}

/**
 * Read the lineage fields off a token without verifying anything.
 *
 * @param {Token} token Any SDK token.
 * @returns {ILineageDescription} What the token claims.
 */
export function describeLineage(token: Token): ILineageDescription {
  let issuer: Uint8Array | null = null;
  if (token.genesis.justification !== null) {
    try {
      issuer = LineageGenesisReason.fromCBOR(token.genesis.justification).issuer;
    } catch {
      issuer = null;
    }
  }
  return {
    issuer,
    revisions: [
      describeRevision(token.genesis.data, token.genesis.recipient, token.genesis.referenceTime),
      ...token.transactions.map((transaction) =>
        describeRevision(transaction.data, transaction.recipient, transaction.referenceTime),
      ),
    ],
    token,
    tokenTypeIsLineage: areUint8ArraysEqual(token.type.bytes, LINEAGE_TOKEN_TYPE.bytes),
  };
}

export interface ILineageVerificationResult {
  readonly description: ILineageDescription;
  /** SDK result tree, or null when it was not reached. */
  readonly details: Result | null;
  readonly reason: string | null;
  readonly status: 'FAIL' | 'OK';
}

/**
 * Rules the SDK does not check, because they relate neighbouring transactions:
 * each revision's index is one more than the previous, and reference times never
 * decrease along the chain (the protocol does not imply this; states can be
 * precomputed and certified out of order).
 */
function chainRules(description: ILineageDescription): Result {
  const results: Result[] = [];
  description.revisions.forEach((revision, position) => {
    if (revision.error !== null) {
      results.push(check(`Revision[${position}]Decodes`, false, `Revision ${position}: ${revision.error}`));
      return;
    }
    results.push(
      check(
        `Revision[${position}]IndexSequential`,
        revision.index === BigInt(position),
        `Revision at position ${position} claims index ${revision.index}.`,
      ),
    );
    const previous = description.revisions[position - 1];
    if (previous !== undefined) {
      results.push(
        check(
          `Revision[${position}]TimeMonotone`,
          revision.referenceTime >= previous.referenceTime,
          `Revision ${position} is certified at ${revision.referenceTime}, before revision ${position - 1} at ${previous.referenceTime}.`,
        ),
      );
    }
  });
  return combine('LineageChainVerification', results);
}

function deepestMessage(result: VerificationResult<unknown>): string {
  if (result.status === VerificationStatus.OK) {
    return '';
  }
  for (const child of result.results) {
    const message = deepestMessage(child);
    if (message !== '') {
      return message;
    }
  }
  return result.message !== '' ? result.message : `Verification rule ${result.rule} failed.`;
}

/**
 * Verify a document lineage token offline: the SDK's full token verification with
 * the lineage issuance policy, then the chain rules.
 *
 * @param {Token} token Token to verify.
 * @param {RootTrustBase} trustBase Trust base of the token's network.
 * @returns {Promise<ILineageVerificationResult>} Outcome.
 */
export async function verifyLineage(token: Token, trustBase: RootTrustBase): Promise<ILineageVerificationResult> {
  const description = describeLineage(token);
  if (!description.tokenTypeIsLineage) {
    return {
      description,
      details: null,
      reason: `Not a document lineage token: token type ${HexConverter.encode(token.type.bytes)}.`,
      status: 'FAIL',
    };
  }
  if (token.networkId.id !== trustBase.networkId.id) {
    return {
      description,
      details: null,
      reason: `The token is for network ${token.networkId.id} and the trust base for network ${trustBase.networkId.id}.`,
      status: 'FAIL',
    };
  }
  const sdk = await token.verify(createLineageVerificationContext(trustBase));
  const details = VerificationResult.fromResults('LineageTokenVerification', [sdk, chainRules(description)]);
  if (details.status !== VerificationStatus.OK) {
    return { description, details, reason: deepestMessage(details), status: 'FAIL' };
  }
  return { description, details, reason: null, status: 'OK' };
}
