import { chmod, lstat, mkdir, readdir, readFile, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { IDurableFileSystem, IWritableFile, NODE_FILE_SYSTEM } from '../../src/commands/durableFile.js';
import { writeRevisionToken } from '../../src/commands/stampRevision.js';
import { testContext } from '../support/context.js';
import { tempDir } from '../support/fixtures.js';

describe('writeRevisionToken', () => {
  const TOKEN = new Uint8Array([0xd9, 0x01, 0x00, 0x82, 0x01, 0x02]);
  const OLD = new TextEncoder().encode('old');
  const appendOverOld = { base: OLD, kind: 'append' } as const;
  const newLineage = { force: false, kind: 'new' } as const;

  it('replaces an existing file without leaving a temporary behind', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    await writeFile(out, 'old');
    const sink = testContext();
    await writeRevisionToken(out, TOKEN, appendOverOld, sink.context);
    expect(new Uint8Array(await readFile(out))).toEqual(TOKEN);
    expect(await readdir(directory)).toEqual(['doc.lineage']);
    expect(sink.stderr()).toEqual('');
  });

  it('never clobbers a file that appeared before a new lineage was written, and prints the token', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    await writeFile(out, 'someone else');
    const sink = testContext();
    await expect(writeRevisionToken(out, TOKEN, newLineage, sink.context)).rejects.toThrow(
      /appeared while the new lineage was being certified/,
    );
    expect(await readFile(out, 'utf8')).toEqual('someone else');
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });

  it('overwrites a file in the way of a new lineage with force', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    await writeFile(out, 'someone else');
    const sink = testContext();
    await writeRevisionToken(out, TOKEN, { force: true, kind: 'new' }, sink.context);
    expect(new Uint8Array(await readFile(out))).toEqual(TOKEN);
    expect(sink.stderr()).toEqual('');
  });

  it('appends through a symlink, keeping the link and the mode', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const shared = await tempDir('proof-cli-revision-shared-');
    const target = path.join(shared, 'doc.lineage');
    await writeFile(target, 'old');
    await chmod(target, 0o640);
    const out = path.join(directory, 'doc.lineage');
    await symlink(target, out);
    await writeRevisionToken(out, TOKEN, appendOverOld, testContext().context);
    expect((await lstat(out)).isSymbolicLink()).toBe(true);
    expect(new Uint8Array(await readFile(target))).toEqual(TOKEN);
    expect((await stat(target)).mode & 0o777).toBe(0o640);
  });

  it.each([
    ['a new lineage', true, []],
    ['an append', false, ['doc.lineage']],
  ])('leaves no partial token when writing %s fails, and prints the token', async (_, created, left) => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    if (!created) {
      await writeFile(out, 'old');
    }
    const failing: IDurableFileSystem = {
      ...NODE_FILE_SYSTEM,
      openNew: async (file, mode): Promise<IWritableFile> => {
        const handle = await NODE_FILE_SYSTEM.openNew(file, mode);
        return {
          close: (): Promise<void> => handle.close(),
          sync: (): Promise<void> => handle.sync(),
          writeFile: async (data): Promise<void> => {
            await handle.writeFile(data.subarray(0, 2));
            throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
          },
        };
      },
    };
    const sink = testContext();
    await expect(
      writeRevisionToken(out, TOKEN, created ? newLineage : appendOverOld, sink.context, failing),
    ).rejects.toThrow(/ENOSPC/);
    expect(await readdir(directory)).toEqual(left);
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });

  it.each([
    ['holds something else', 'newer'],
    ['is gone', null],
  ])('leaves an append unwritten when the file %s, and says so without printing', async (_, now) => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    if (now !== null) {
      await writeFile(out, now);
    }
    const sink = testContext();
    expect(await writeRevisionToken(out, TOKEN, appendOverOld, sink.context)).toEqual('changed');
    expect(await readdir(directory)).toEqual(now === null ? [] : ['doc.lineage']);
    if (now !== null) {
      expect(await readFile(out, 'utf8')).toEqual(now);
    }
    expect(sink.stderr()).toEqual('');
  });

  it('prints the token when the directory is gone', async () => {
    const directory = await tempDir('proof-cli-revision-');
    await mkdir(path.join(directory, 'sub'));
    const sink = testContext();
    await expect(
      writeRevisionToken(path.join(directory, 'missing', 'doc.lineage'), TOKEN, appendOverOld, sink.context),
    ).rejects.toThrow(/ENOENT/);
    expect(sink.stderr()).toContain('the revision was certified');
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });
});
