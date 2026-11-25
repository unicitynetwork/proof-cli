import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  findJournals,
  IPendingRevision,
  journalPath,
  readJournal,
  writeJournal,
} from '../../src/commands/revisionJournal.js';
import { EXIT_USAGE, toExitCode } from '../../src/errors.js';
import { OTHER_DIGEST, tempDir, TEST_DIGEST } from '../support/fixtures.js';

describe('revision journals', () => {
  const pending: IPendingRevision = {
    digest: TEST_DIGEST,
    nextProducer: null,
    revision: 1n,
    tokenId: new Uint8Array(32).fill(0xaa),
    transaction: new Uint8Array([1, 2, 3]),
  };
  let directory: string;
  let tokenFile: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-journal-');
    tokenFile = path.join(directory, 'doc.lineage');
  });

  it('names a journal after its transfer, so candidates for one revision sit side by side', async () => {
    const first = journalPath(tokenFile, pending.transaction);
    const second = journalPath(tokenFile, new Uint8Array([4, 5, 6]));
    expect(path.basename(first)).toMatch(/^\.doc\.lineage\.[0-9a-f]{16}\.pending$/);
    expect(second).not.toEqual(first);
    expect(await writeJournal(first, pending)).toBe(true);
    expect(await writeJournal(second, { ...pending, transaction: new Uint8Array([4, 5, 6]) })).toBe(true);
    await writeFile(path.join(directory, '.other.lineage.0000000000000000.pending'), 'not ours');
    await writeFile(path.join(directory, '.doc.lineage.pending'), 'not a journal name');
    expect(await findJournals(tokenFile)).toEqual([first, second].sort());
    expect(await readJournal(first)).toEqual(pending);
  });

  it('accepts a journal another run already wrote for the same transfer, and leaves it as it is', async () => {
    const file = journalPath(tokenFile, pending.transaction);
    await writeJournal(file, pending);
    const written = await readFile(file, 'utf8');
    expect(await writeJournal(file, pending)).toBe(false);
    expect(await readFile(file, 'utf8')).toEqual(written);
  });

  // MastaP on PR #16: the loser of a race to create the journal deleted the winner's.
  it('never removes a journal it did not create, even one with other content', async () => {
    const file = journalPath(tokenFile, pending.transaction);
    await writeJournal(file, { ...pending, digest: OTHER_DIGEST });
    const written = await readFile(file, 'utf8');
    const attempt = writeJournal(file, pending);
    await expect(attempt).rejects.toThrow(/already exists with other content; nothing was submitted/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
    expect(await readFile(file, 'utf8')).toEqual(written);

    await writeFile(file, 'garbage');
    await expect(writeJournal(file, pending)).rejects.toThrow(/is not a pending lineage revision/);
    expect(await readFile(file, 'utf8')).toEqual('garbage');
    expect(await readdir(directory)).toEqual([path.basename(file)]);
  });
});
