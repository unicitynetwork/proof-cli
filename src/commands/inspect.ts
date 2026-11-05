import { ICommandContext } from './context.js';
import { decodeToken, readTokenInput, reportNotAToken } from './tokenInput.js';
import { EXIT_OK } from '../errors.js';
import { describeLineage } from '../lib/LineageVerification.js';
import { describeToken } from '../lib/TimestampVerification.js';
import { inspectJson, inspectText, lineageInspectJson, lineageInspectText, toJsonLine } from '../output.js';

/**
 * `inspect`: decode and print a token without verifying anything. Document lineage
 * tokens are shown revision by revision; every other type as a timestamp.
 *
 * @param {string} file Token path, or `-` for stdin.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code: 0 if the bytes decode as a token, 1 otherwise.
 */
export async function runInspect(file: string, context: ICommandContext): Promise<number> {
  const decoded = await decodeToken(await readTokenInput(file, context.stdin));
  if (decoded.token === null) {
    return reportNotAToken(context, 'inspect', decoded.error);
  }
  const lineage = describeLineage(decoded.token);
  if (lineage.tokenTypeIsLineage) {
    context.stdout.write(context.json ? toJsonLine(lineageInspectJson(lineage)) : `${lineageInspectText(lineage)}\n`);
    return EXIT_OK;
  }
  const description = describeToken(decoded.token);
  context.stdout.write(context.json ? toJsonLine(inspectJson(description)) : `${inspectText(description)}\n`);
  return EXIT_OK;
}
