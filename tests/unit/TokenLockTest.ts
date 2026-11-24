import { readdir, readFile, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { acquireAppendLock } from '../../src/commands/tokenLock.js';
import { EXIT_USAGE, toExitCode } from '../../src/errors.js';
import { tempDir } from '../support/fixtures.js';

describe('acquireAppendLock', () => {
  let directory: string;
  let tokenFile: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-lock-');
    tokenFile = path.join(directory, 'doc.lineage');
    await writeFile(tokenFile, 'token');
  });

  it('creates a lock naming its holder next to the token file, and removes it on release', async () => {
    const release = await acquireAppendLock(tokenFile);
    expect(JSON.parse(await readFile(path.join(directory, '.doc.lineage.lock'), 'utf8'))).toMatchObject({
      format: 'unicity-proof/append-lock',
      pid: process.pid,
    });
    await release();
    expect(await readdir(directory)).toEqual(['doc.lineage']);
  });

  it('refuses while the lock is held, also through another path to the same file', async () => {
    const release = await acquireAppendLock(tokenFile);
    const other = await tempDir('proof-cli-lock-link-');
    const link = path.join(other, 'linked.lineage');
    await symlink(tokenFile, link);
    for (const file of [tokenFile, link]) {
      const attempt = acquireAppendLock(file);
      await expect(attempt).rejects.toThrow(
        new RegExp(`^Another stamp-revision run is appending to ${file} \\(pid ${process.pid} on .+, since .+\\)`),
      );
      expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
    }
    expect(await readdir(other)).toEqual(['linked.lineage']);
    await release();
    const again = await acquireAppendLock(link);
    await again();
  });

  it('describes a lock it cannot read without the details, and still refuses', async () => {
    await writeFile(path.join(directory, '.doc.lineage.lock'), 'garbage');
    await expect(acquireAppendLock(tokenFile)).rejects.toThrow(
      `Another stamp-revision run is appending to ${tokenFile}; nothing was submitted.`,
    );
  });

  it('never removes a lock that is no longer its own', async () => {
    const release = await acquireAppendLock(tokenFile);
    const lock = path.join(directory, '.doc.lineage.lock');
    await writeFile(lock, 'another run, after this one was deleted as stale');
    await release();
    expect(await readFile(lock, 'utf8')).toEqual('another run, after this one was deleted as stale');
  });
});
