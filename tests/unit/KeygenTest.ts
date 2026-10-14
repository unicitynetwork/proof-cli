import { chmod, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runKeygen } from '../../src/commands/keygen.js';
import { testContext } from '../support/context.js';
import { tempDir } from '../support/fixtures.js';

// `writeFile`'s mode is masked by the process umask, so a umask covering owner
// bits would otherwise produce a key file at 0200 or 0000 -- unreadable by the
// signing path that needs it -- while the summary still reported 0600.
describe('runKeygen under a umask that masks owner bits', () => {
  let directory: string;
  let previousUmask: number;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-umask-');
    previousUmask = process.umask(0o477);
  });

  afterEach(() => {
    process.umask(previousUmask);
  });

  it('still creates a readable 0600 key', async () => {
    const out = path.join(directory, 'fresh.key');
    await runKeygen({ out }, testContext().context);
    expect((await stat(out)).mode & 0o777).toBe(0o600);
    expect((await readFile(out, 'utf8')).trim()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('still creates a readable 0600 key when replacing an existing file', async () => {
    const out = path.join(directory, 'existing.key');
    await writeFile(out, 'placeholder\n', { mode: 0o644 });
    await runKeygen({ force: true, out }, testContext().context);
    expect((await stat(out)).mode & 0o777).toBe(0o600);
    expect((await readFile(out, 'utf8')).trim()).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('runKeygen when the staged write cannot complete', () => {
  let directory: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-keygen-fail-');
  });

  afterEach(async () => {
    await chmod(directory, 0o700).catch(() => undefined);
  });

  // The forced path stages the key in a sibling file. If that write or the rename
  // fails, the cleanup must not mask the error that caused it, and must not leave
  // a stray key fragment next to the target.
  it('surfaces the real error and leaves no staged key behind', async () => {
    const out = path.join(directory, 'target.key');
    await writeFile(out, 'placeholder\n', { mode: 0o600 });
    await chmod(directory, 0o500);

    await expect(runKeygen({ force: true, out }, testContext().context)).rejects.toThrow(/EACCES|EPERM/);

    await chmod(directory, 0o700);
    expect(await readdir(directory)).toEqual(['target.key']);
    expect(await readFile(out, 'utf8')).toEqual('placeholder\n');
  });
});
