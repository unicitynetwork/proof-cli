import { ICommandContext } from './context.js';
import { decodeToken, readTokenInput, reportNotAToken } from './tokenInput.js';
import {
  assertOneDigestSource,
  INetworkFlags,
  parseTokenId,
  resolveDigest,
  resolveTrustBaseOverride,
} from '../config.js';
import { EXIT_OK, EXIT_VERIFICATION_FAILED, usageError } from '../errors.js';
import { describeLineage, ILineageVerificationResult, verifyLineage } from '../lib/LineageVerification.js';
import { bundledTrustBase, ITrustBaseChoice, networkNameForId, TrustBaseSource } from '../lib/networks.js';
import {
  describeToken,
  ITimestampVerificationResult,
  verificationFailure,
  verify,
} from '../lib/TimestampVerification.js';
import { lineageVerifyJson, lineageVerifyText, toJsonLine, verifyJson, verifyText } from '../output.js';

export interface IVerifyFlags extends INetworkFlags {
  readonly file?: string;
  readonly hash?: string;
  readonly tokenId?: string;
}

function report(
  context: ICommandContext,
  result: ITimestampVerificationResult,
  source: TrustBaseSource | null,
): number {
  context.stdout.write(context.json ? toJsonLine(verifyJson(result, source)) : `${verifyText(result, source)}\n`);
  return result.status === 'OK' ? EXIT_OK : EXIT_VERIFICATION_FAILED;
}

function reportLineage(
  context: ICommandContext,
  result: ILineageVerificationResult,
  source: TrustBaseSource | null,
): number {
  context.stdout.write(
    context.json ? toJsonLine(lineageVerifyJson(result, source)) : `${lineageVerifyText(result, source)}\n`,
  );
  return result.status === 'OK' ? EXIT_OK : EXIT_VERIFICATION_FAILED;
}

/**
 * `verify`: check a token offline and report what it proves. A document lineage
 * token is verified as a lineage, an expected token id is compared, and an
 * expected digest is looked for among its revisions; any other token is verified
 * as a timestamp. Cheap failures come first; the document is hashed only once the token and trust base are in hand.
 *
 * @param {string} file Token path, or `-` for stdin.
 * @param {IVerifyFlags} flags Command flags.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code.
 */
export async function runVerify(file: string, flags: IVerifyFlags, context: ICommandContext): Promise<number> {
  // Before anything is read: the paths below report a token they cannot place as
  // a failed verification, which would answer a contradictory command line with
  // exit 1 and no mention of the contradiction.
  assertOneDigestSource(flags.hash, flags.file, '--hash');
  const expectedTokenId = flags.tokenId === undefined ? undefined : parseTokenId(flags.tokenId);

  const decoded = await decodeToken(await readTokenInput(file, context.stdin));
  if (decoded.token === null) {
    return reportNotAToken(context, 'verify', decoded.error);
  }
  const token = decoded.token;
  const lineage = describeLineage(token);
  if (expectedTokenId !== undefined && !lineage.tokenTypeIsLineage) {
    // A timestamp has no successors, so its id distinguishes nothing; quietly
    // ignoring the flag would suggest it had been checked.
    throw usageError('--token-id applies to document lineage tokens only; this token is not one.');
  }

  let choice = await resolveTrustBaseOverride(flags);
  if (choice === undefined) {
    const name = networkNameForId(token.networkId.id);
    if (name === undefined) {
      const reason = `unknown network id ${token.networkId.id}; pass --trust-base`;
      if (lineage.tokenTypeIsLineage) {
        return reportLineage(
          context,
          {
            description: lineage,
            details: null,
            matchingRevisions: null,
            reason,
            status: 'FAIL',
            tokenIdMatches: null,
          },
          null,
        );
      }
      return report(context, verificationFailure(describeToken(token), reason), null);
    }
    choice = {
      source: { kind: 'bundled', network: name },
      trustBase: bundledTrustBase(name),
    } satisfies ITrustBaseChoice;
  }

  const expectedDigest = await resolveDigest(flags.hash, flags.file, '--hash');
  if (lineage.tokenTypeIsLineage) {
    return reportLineage(
      context,
      await verifyLineage(token, choice.trustBase, { expectedDigest, expectedTokenId }),
      choice.source,
    );
  }
  return report(context, await verify(token, choice.trustBase, { expectedDigest }), choice.source);
}
