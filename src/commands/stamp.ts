import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import { ICommandContext } from './context.js';
import { IStampFlags, resolveStampConfig } from '../config.js';
import { EXIT_OK } from '../errors.js';
import { describeToken, stamp } from '../lib/TimestampClient.js';
import { recoveryLines, stampJson, stampText, toJsonLine, warningLine } from '../output.js';

/**
 * Persist a token that has already been certified and billed.
 *
 * By the time this runs the stamp is spent and the bytes exist nowhere else, so
 * the one thing it must never do is fail silently. Whatever goes wrong, the token
 * is printed as hex — which `verify` and `inspect` both accept — before the error
 * propagates, so a write that cannot be completed does not destroy the stamp.
 *
 * The write itself is left as a single exclusive `writeFile`: it is the form that
 * works on every destination, including removable filesystems with no hard links,
 * and staging through a temporary file bought atomicity at the cost of several new
 * ways to fail after billing. A truncated file is still recoverable from the hex.
 *
 * Exported so the recovery path has test coverage: it only runs after a stamp has
 * been paid for, which no test can reach through `runStamp` without a gateway.
 *
 * @param {string} out Absolute output path.
 * @param {Uint8Array} bytes Encoded token.
 * @param {boolean} force Whether an existing file may be replaced.
 * @param {ICommandContext} context Streams.
 */
export async function writeCertifiedToken(
  out: string,
  bytes: Uint8Array,
  force: boolean,
  context: ICommandContext,
): Promise<void> {
  try {
    await writeFile(out, bytes, { flag: force ? 'w' : 'wx' });
  } catch (error) {
    // First statement in the handler, with nothing awaited before it, so no
    // further failure can get between the error and the recovered bytes.
    context.stderr.write(recoveryLines(bytes));
    throw error;
  }
}

/**
 * `stamp`: certify a digest, write the token, print the summary.
 *
 * @param {string} [digestArgument] Positional digest.
 * @param {IStampFlags} flags Command flags.
 * @param {ICommandContext} context Streams and interrupt signal.
 * @returns {Promise<number>} Exit code.
 */
export async function runStamp(
  digestArgument: string | undefined,
  flags: IStampFlags,
  context: ICommandContext,
): Promise<number> {
  const config = await resolveStampConfig(digestArgument, flags);

  const token = await stamp(config.digest, config.network, config.apiKey, {
    allowInsecureTransport: config.allowInsecure,
    onWarning: (message): void => {
      context.stderr.write(warningLine(message));
    },
    signal: context.interrupt,
    signer: config.signer,
    timeoutMs: config.timeoutMs,
  });

  const bytes = token.toCBOR();
  const out = config.out === '-' ? null : path.resolve(config.out);
  if (out === null) {
    context.stdout.write(bytes);
  } else {
    await writeCertifiedToken(out, bytes, config.force, context);
  }

  const summary = out === null ? context.stderr : context.stdout;
  const description = describeToken(token);
  summary.write(
    context.json
      ? toJsonLine(stampJson(description, config.network.gatewayUrl, out, bytes))
      : `${stampText(description, config.network.gatewayUrl, out)}\n`,
  );
  return EXIT_OK;
}
