import { readFile, realpath, rm } from 'node:fs/promises';
import { hostname } from 'node:os';
import path from 'node:path';

import { IDurableFileSystem, NODE_FILE_SYSTEM, writeExclusive } from './durableFile.js';
import { hasErrorCode } from './revisionJournal.js';
import { usageError } from '../errors.js';

const LOCK_FORMAT = 'unicity-proof/append-lock';

interface ILockJson {
  readonly format: typeof LOCK_FORMAT;
  readonly host: string;
  readonly pid: number;
  readonly started: string;
}

/**
 * @param {string} realTokenFile The token file, with symlinks resolved.
 * @returns {string} Its lock: `.<name>.lock` next to it.
 */
export function lockPath(realTokenFile: string): string {
  return path.join(path.dirname(realTokenFile), `.${path.basename(realTokenFile)}.lock`);
}

function describeHolder(text: string): string {
  try {
    const json = JSON.parse(text) as Partial<ILockJson>;
    if (json.format === LOCK_FORMAT) {
      return ` (pid ${json.pid} on ${json.host}, since ${json.started})`;
    }
  } catch {
    // Described without the details, then.
  }
  return '';
}

/**
 * Take the append lock of a token file, so that two `stamp-revision` runs cannot
 * append to it at once: a slower one would write its token over the faster one's,
 * and a revision certified and written in between would vanish from the file.
 *
 * The lock is a file created exclusively next to the token file, after symlinks
 * are resolved, so every path to the same file shares one lock. It holds no data:
 * it only says who holds it, and deleting it when no run is active is always safe.
 *
 * The lock is created with {@link writeExclusive}, so a lock whose contents
 * cannot be written is removed again: it is this run's, and left behind it would
 * refuse every later append until someone deleted it.
 *
 * @param {string} tokenFile Absolute token file path; it must exist.
 * @param {IDurableFileSystem} [fs] File operations, for tests.
 * @returns {Promise<() => Promise<void>>} Releases the lock; never fails.
 * @throws {CliError} If another run holds the lock, or it cannot be taken; nothing has been submitted then.
 */
export async function acquireAppendLock(
  tokenFile: string,
  fs: IDurableFileSystem = NODE_FILE_SYSTEM,
): Promise<() => Promise<void>> {
  let file: string;
  try {
    file = lockPath(await realpath(tokenFile));
  } catch (error) {
    throw usageError(`Cannot read the token file ${tokenFile}.`, { cause: error });
  }
  const json: ILockJson = {
    format: LOCK_FORMAT,
    host: hostname(),
    pid: process.pid,
    started: new Date().toISOString(),
  };
  const contents = `${JSON.stringify(json, null, 2)}\n`;
  try {
    await writeExclusive(fs, file, new TextEncoder().encode(contents), 0o644);
  } catch (error) {
    if (hasErrorCode(error, 'EEXIST')) {
      const holder = describeHolder(await readFile(file, 'utf8').catch(() => ''));
      throw usageError(
        `Another stamp-revision run is appending to ${tokenFile}${holder}; nothing was submitted. ` +
          `Wait for it to finish. If no run is active, delete the lock file ${file}: it holds no data.`,
        { cause: error },
      );
    }
    throw usageError(`Cannot create the lock file ${file}; nothing was submitted.`, { cause: error });
  }
  return async (): Promise<void> => {
    // Only this run's lock: if someone deleted it as stale while this run was going,
    // and another run took it since, that one is not this run's to remove.
    const now = await readFile(file, 'utf8').catch(() => null);
    if (now === contents) {
      await rm(file, { force: true }).catch(() => undefined);
    }
  };
}
