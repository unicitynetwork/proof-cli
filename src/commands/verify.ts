import { ICommandContext } from './context.js';
import { decodeToken, readTokenInput, reportNotAToken } from './tokenInput.js';
import { INetworkFlags, resolveDigest, resolveTrustBaseOverride } from '../config.js';
import { EXIT_OK, EXIT_VERIFICATION_FAILED } from '../errors.js';
import { bundledTrustBase, ITrustBaseChoice, networkNameForId, TrustBaseSource } from '../lib/networks.js';
import { describeToken, ITimestampVerificationResult, verificationFailure, verify } from '../lib/TimestampClient.js';
import { toJsonLine, verifyJson, verifyText } from '../output.js';

export interface IVerifyFlags extends INetworkFlags {
  readonly file?: string;
  readonly hash?: string;
}

function report(
  context: ICommandContext,
  result: ITimestampVerificationResult,
  source: TrustBaseSource | null,
): number {
  context.stdout.write(context.json ? toJsonLine(verifyJson(result, source)) : `${verifyText(result, source)}\n`);
  return result.status === 'OK' ? EXIT_OK : EXIT_VERIFICATION_FAILED;
}

/**
 * `verify`: check a token offline and report what it proves. Cheap failures
 * come first; the document is hashed only once the token and trust base are in hand.
 *
 * @param {string} file Token path, or `-` for stdin.
 * @param {IVerifyFlags} flags Command flags.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code.
 */
export async function runVerify(file: string, flags: IVerifyFlags, context: ICommandContext): Promise<number> {
  const decoded = await decodeToken(await readTokenInput(file, context.stdin));
  if (decoded.token === null) {
    return reportNotAToken(context, 'verify', decoded.error);
  }
  const token = decoded.token;

  let choice = await resolveTrustBaseOverride(flags);
  if (choice === undefined) {
    const name = networkNameForId(token.networkId.id);
    if (name === undefined) {
      return report(
        context,
        verificationFailure(describeToken(token), `unknown network id ${token.networkId.id}; pass --trust-base`),
        null,
      );
    }
    choice = {
      source: { kind: 'bundled', network: name },
      trustBase: bundledTrustBase(name),
    } satisfies ITrustBaseChoice;
  }

  const expectedDigest = await resolveDigest(flags.hash, flags.file, '--hash');
  return report(context, await verify(token, choice.trustBase, { expectedDigest }), choice.source);
}
