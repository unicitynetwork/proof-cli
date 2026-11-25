import { createHash } from 'node:crypto';
import { open, readdir, readFile, rm } from 'node:fs/promises';
import path from 'node:path';

import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { TransferTransaction } from '@unicitylabs/state-transition-sdk/lib/transaction/TransferTransaction.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { areUint8ArraysEqual } from '@unicitylabs/state-transition-sdk/lib/util/TypedArrayUtils.js';

import { usageError } from '../errors.js';
import { IPreparedRevision, isSameRevision, nextRevisionIndex } from '../lib/LineageClient.js';

/**
 * A revision submitted to the aggregator but not yet written to the token file.
 * The aggregator keeps only the transaction's hash, so until the token file holds
 * the revision, this is the only record of what was certified.
 */
export interface IPendingRevision {
  readonly digest: Uint8Array;
  /** Null when the revision is a seal. */
  readonly nextProducer: Uint8Array | null;
  readonly revision: bigint;
  readonly tokenId: Uint8Array;
  /** The transfer, CBOR-encoded. */
  readonly transaction: Uint8Array;
}

const JOURNAL_FORMAT = 'unicity-proof/pending-revision';
const JOURNAL_VERSION = 1;

interface IJournalJson {
  readonly digest: string;
  readonly format: typeof JOURNAL_FORMAT;
  readonly nextProducer: string | null;
  readonly revision: string;
  readonly tokenId: string;
  readonly transaction: string;
  readonly version: typeof JOURNAL_VERSION;
}

const JOURNAL_SUFFIX = '.pending';

/**
 * One journal per transaction, so that two candidates for the same revision, from
 * runs with different inputs, can be kept side by side until one is certified.
 *
 * @param {string} tokenFile Absolute token file path.
 * @param {Uint8Array} transaction The journaled transfer, CBOR-encoded.
 * @returns {string} Its journal next to the token file: `.<name>.<first 16 hex of SHA-256(transfer)>.pending`.
 */
export function journalPath(tokenFile: string, transaction: Uint8Array): string {
  const tag = createHash('sha256').update(transaction).digest('hex').slice(0, 16);
  return path.join(path.dirname(tokenFile), `.${path.basename(tokenFile)}.${tag}${JOURNAL_SUFFIX}`);
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Every journal next to the token file, in name order. A journal is matched by
 * its name's pattern only; its tag is not checked against its contents, which
 * are checked against the token file when it is acted on.
 *
 * @param {string} tokenFile Absolute token file path.
 * @returns {Promise<string[]>} Journal paths.
 * @throws {CliError} If the directory cannot be listed.
 */
export async function findJournals(tokenFile: string): Promise<string[]> {
  const directory = path.dirname(tokenFile);
  const pattern = new RegExp(`^\\.${escapeRegExp(path.basename(tokenFile))}\\.[0-9a-f]{16}\\.pending$`);
  let names: string[];
  try {
    names = await readdir(directory);
  } catch (error) {
    throw usageError(`Cannot list ${directory} to look for journals of ${tokenFile}.`, { cause: error });
  }
  return names
    .filter((name) => pattern.test(name))
    .sort()
    .map((name) => path.join(directory, name));
}

/**
 * @param {Token} token The token the revision was prepared for.
 * @param {IPreparedRevision} prepared The prepared revision.
 * @param {Uint8Array} digest Its digest.
 * @param {Uint8Array|null} nextProducer Its next producer; null for a seal.
 * @returns {IPendingRevision} What the journal records.
 */
export function pendingRevision(
  token: Token,
  prepared: IPreparedRevision,
  digest: Uint8Array,
  nextProducer: Uint8Array | null,
): IPendingRevision {
  return {
    digest,
    nextProducer,
    revision: prepared.index,
    tokenId: token.id.bytes,
    transaction: prepared.transaction.toCBOR(),
  };
}

/**
 * @param {unknown} error Thrown value.
 * @param {string} code Node error code, such as `ENOENT`.
 * @returns {boolean} Whether the error carries that code.
 */
export function hasErrorCode(error: unknown, code: string): boolean {
  // Not `instanceof Error`: errors from Node's fs need not come from this realm's Error.
  return typeof error === 'object' && error !== null && (error as NodeJS.ErrnoException).code === code;
}

function samePending(a: IPendingRevision, b: IPendingRevision): boolean {
  return (
    a.revision === b.revision &&
    areUint8ArraysEqual(a.digest, b.digest) &&
    areUint8ArraysEqual(a.tokenId, b.tokenId) &&
    areUint8ArraysEqual(a.transaction, b.transaction) &&
    (a.nextProducer === null
      ? b.nextProducer === null
      : b.nextProducer !== null && areUint8ArraysEqual(a.nextProducer, b.nextProducer))
  );
}

/**
 * Write the journal durably, before the revision is submitted: an exclusive
 * create, then an fsync of the file and, where the platform allows, of its
 * directory, so a crash cannot leave the name pointing at nothing.
 *
 * A journal that is already there, for the same transfer, is another run's record
 * of the very request this run is about to make, and is used as it is. Anything
 * this call did not create is never removed.
 *
 * @param {string} file Journal path.
 * @param {IPendingRevision} pending What to record.
 * @returns {Promise<boolean>} True if this call created the journal; false if it was already there.
 * @throws {CliError} If the journal cannot be written, or holds something else; nothing has been submitted then.
 */
export async function writeJournal(file: string, pending: IPendingRevision): Promise<boolean> {
  const json: IJournalJson = {
    digest: HexConverter.encode(pending.digest),
    format: JOURNAL_FORMAT,
    nextProducer: pending.nextProducer === null ? null : HexConverter.encode(pending.nextProducer),
    revision: pending.revision.toString(),
    tokenId: HexConverter.encode(pending.tokenId),
    transaction: HexConverter.encode(pending.transaction),
    version: JOURNAL_VERSION,
  };
  let handle;
  try {
    handle = await open(file, 'wx');
  } catch (error) {
    if (hasErrorCode(error, 'EEXIST')) {
      const existing = await readJournal(file);
      if (existing !== null && samePending(existing, pending)) {
        return false;
      }
      throw usageError(
        `The journal ${file} already exists with other content; nothing was submitted. ` +
          'Move it away if it is not needed.',
        { cause: error },
      );
    }
    throw usageError(`Cannot write the journal ${file}; nothing was submitted.`, { cause: error });
  }
  try {
    try {
      await handle.writeFile(`${JSON.stringify(json, null, 2)}\n`);
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    // This call created the file, so it is this call's to remove.
    await rm(file, { force: true }).catch(() => undefined);
    throw usageError(`Cannot write the journal ${file}; nothing was submitted.`, { cause: error });
  }
  try {
    const directory = await open(path.dirname(file), 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
  } catch {
    // Not every platform can open or sync a directory; the file itself is synced.
  }
  return true;
}

/**
 * @param {string} file Journal path.
 */
export async function removeJournal(file: string): Promise<void> {
  await rm(file, { force: true });
}

function unreadable(file: string, detail: string, cause?: unknown): Error {
  return usageError(
    `The journal ${file} is not a pending lineage revision (${detail}). Move it away if it is not needed.`,
    { cause },
  );
}

function hexField(file: string, value: unknown, name: string): Uint8Array {
  if (typeof value !== 'string' || !/^([0-9a-f]{2})+$/.test(value)) {
    throw unreadable(file, `bad ${name}`);
  }
  return HexConverter.decode(value);
}

/**
 * Read the journal, if there is one.
 *
 * @param {string} file Journal path.
 * @returns {Promise<IPendingRevision|null>} The pending revision, or null without a journal.
 * @throws {CliError} If the file exists but is not a journal this version wrote.
 */
export async function readJournal(file: string): Promise<IPendingRevision | null> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    if (hasErrorCode(error, 'ENOENT')) {
      return null;
    }
    throw usageError(`Cannot read the journal ${file}.`, { cause: error });
  }
  let json: Partial<Record<keyof IJournalJson, unknown>>;
  try {
    json = JSON.parse(text) as typeof json;
  } catch (error) {
    throw unreadable(file, 'not JSON', error);
  }
  if (json.format !== JOURNAL_FORMAT || json.version !== JOURNAL_VERSION) {
    throw unreadable(file, 'unknown format');
  }
  if (typeof json.revision !== 'string' || !/^[1-9][0-9]*$/.test(json.revision)) {
    throw unreadable(file, 'bad revision');
  }
  return {
    digest: hexField(file, json.digest, 'digest'),
    nextProducer: json.nextProducer === null ? null : hexField(file, json.nextProducer, 'nextProducer'),
    revision: BigInt(json.revision),
    tokenId: hexField(file, json.tokenId, 'tokenId'),
    transaction: hexField(file, json.transaction, 'transaction'),
  };
}

/** Where a journal stands against the token file it sits next to. */
export type JournalStanding =
  /** The token file already holds this revision: the journal is left over from a run that finished writing. */
  | { readonly kind: 'written' }
  /** The journal is for the token file's next revision; recover it if it was certified. */
  | { readonly kind: 'next'; readonly transaction: TransferTransaction };

/**
 * Relate a journal to the token file. Only a journal that is provably redundant,
 * or provably for the next revision of this very lineage, is acted on; anything
 * else stops the command, so that nothing is thrown away unread.
 *
 * @param {string} file Journal path, for messages.
 * @param {IPendingRevision} pending The journal's contents.
 * @param {Token} token The token file's lineage.
 * @param {string} tokenFile Token file path, for messages.
 * @returns {Promise<JournalStanding>} What to do with the journal.
 * @throws {CliError} If the journal belongs to another lineage, to a later revision, or does not hang together.
 */
export async function journalStanding(
  file: string,
  pending: IPendingRevision,
  token: Token,
  tokenFile: string,
): Promise<JournalStanding> {
  if (!areUint8ArraysEqual(pending.tokenId, token.id.bytes)) {
    throw usageError(
      `The journal ${file} is for lineage ${HexConverter.encode(pending.tokenId)}, but ${tokenFile} holds ` +
        `lineage ${HexConverter.encode(token.id.bytes)}. Move the journal away if it is not needed.`,
    );
  }
  const next = nextRevisionIndex(token);
  if (pending.revision < next) {
    return { kind: 'written' };
  }
  if (pending.revision > next) {
    throw usageError(
      `The journal ${file} is for revision ${pending.revision}, but ${tokenFile} ends at revision ${next - 1n}: ` +
        'the token file is out of date. Get the current one, or move the journal away if it is not needed.',
    );
  }
  const tip = token.latestTransaction;
  let transaction: TransferTransaction;
  try {
    transaction = TransferTransaction.fromCBOR(pending.transaction, await tip.calculateStateHash(), tip.recipient);
  } catch (error) {
    throw unreadable(file, 'bad transaction', error);
  }
  if (!(await isSameRevision(transaction, pending.revision, pending.digest, pending.nextProducer))) {
    throw unreadable(file, 'the digest or next producer does not match the transaction');
  }
  return { kind: 'next', transaction };
}
