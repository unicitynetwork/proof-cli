import { chmod, lstat, readdir, readFile, readlink, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { IDurableFileSystem, NODE_FILE_SYSTEM, writeFileDurably } from '../../src/commands/durableFile.js';
import { tempDir } from '../support/fixtures.js';

const DATA = new TextEncoder().encode('new contents\n');

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

/** The real file system, with `writeNew` writing only the first three bytes of `fail` before failing. */
function failingWrite(fail: (file: string) => boolean): IDurableFileSystem {
  return {
    ...NODE_FILE_SYSTEM,
    writeNew: async (file, data, mode): Promise<void> => {
      if (!fail(file)) {
        return NODE_FILE_SYSTEM.writeNew(file, data, mode);
      }
      await NODE_FILE_SYSTEM.writeNew(file, data.subarray(0, 3), mode);
      throw errno('ENOSPC');
    },
  };
}

const noLink = (): Promise<void> => Promise.reject(errno('EPERM'));

/** The real file system on a filesystem without hard links. */
const NO_LINKS: IDurableFileSystem = { ...NODE_FILE_SYSTEM, link: noLink };

describe('writeFileDurably', () => {
  let directory: string;
  let file: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-durable-');
    file = path.join(directory, 'doc.lineage');
  });

  describe('create', () => {
    const create = { followSymlinks: false, publish: 'create' } as const;

    it('writes the file and leaves no temporary behind', async () => {
      await writeFileDurably(file, DATA, create);
      expect(new Uint8Array(await readFile(file))).toEqual(DATA);
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it('refuses an existing file with EEXIST naming it, not the temporary', async () => {
      await writeFile(file, 'someone else');
      await expect(writeFileDurably(file, DATA, create)).rejects.toMatchObject({ code: 'EEXIST', path: file });
      expect(await readFile(file, 'utf8')).toEqual('someone else');
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it('refuses a symlink to a missing file', async () => {
      await symlink(path.join(directory, 'target'), file);
      await expect(writeFileDurably(file, DATA, create)).rejects.toMatchObject({ code: 'EEXIST', path: file });
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it('creates the file a symlink chain points to when following symlinks, and keeps the links', async () => {
      const target = path.join(directory, 'sub-target');
      await symlink('middle', file);
      await symlink(target, path.join(directory, 'middle'));
      await writeFileDurably(file, DATA, { ...create, followSymlinks: true });
      expect(new Uint8Array(await readFile(target))).toEqual(DATA);
      expect(await readlink(file)).toEqual('middle');
    });

    it('never leaves a partial file at the name when the write fails', async () => {
      await expect(
        writeFileDurably(
          file,
          DATA,
          create,
          failingWrite(() => true),
        ),
      ).rejects.toMatchObject({
        code: 'ENOSPC',
      });
      expect(await readdir(directory)).toEqual([]);
    });

    it('creates the file itself without hard links', async () => {
      await writeFileDurably(file, DATA, { ...create, fileMode: 0o600 }, NO_LINKS);
      expect(new Uint8Array(await readFile(file))).toEqual(DATA);
      expect((await stat(file)).mode & 0o777).toBe(0o600);
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it('without hard links, still refuses an existing file and removes a partial one', async () => {
      await writeFile(file, 'someone else');
      await expect(writeFileDurably(file, DATA, create, NO_LINKS)).rejects.toMatchObject({
        code: 'EEXIST',
        path: file,
      });
      expect(await readFile(file, 'utf8')).toEqual('someone else');

      const other = path.join(directory, 'other.lineage');
      const failing = { ...failingWrite((name) => name === other), link: noLink };
      await expect(writeFileDurably(other, DATA, create, failing)).rejects.toMatchObject({ code: 'ENOSPC' });
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });
  });

  describe('replace', () => {
    const replace = { followSymlinks: true, publish: 'replace' } as const;

    it('keeps the old file intact when the write fails', async () => {
      await writeFile(file, 'old');
      await expect(
        writeFileDurably(
          file,
          DATA,
          replace,
          failingWrite(() => true),
        ),
      ).rejects.toMatchObject({
        code: 'ENOSPC',
      });
      expect(await readFile(file, 'utf8')).toEqual('old');
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });

    it("keeps the file's mode", async () => {
      await writeFile(file, 'old');
      await chmod(file, 0o640);
      await writeFileDurably(file, DATA, replace);
      expect(new Uint8Array(await readFile(file))).toEqual(DATA);
      expect((await stat(file)).mode & 0o777).toBe(0o640);
    });

    it('sets an explicit mode instead, whatever the old one was', async () => {
      await writeFile(file, 'old', { mode: 0o644 });
      await writeFileDurably(file, DATA, { ...replace, fileMode: 0o600 });
      expect((await stat(file)).mode & 0o777).toBe(0o600);
    });

    it('writes through a symlink, which keeps pointing at the file', async () => {
      const shared = await tempDir('proof-cli-durable-shared-');
      const target = path.join(shared, 'doc.lineage');
      await writeFile(target, 'old');
      await chmod(target, 0o640);
      await symlink(target, file);
      await writeFileDurably(file, DATA, replace);
      expect((await lstat(file)).isSymbolicLink()).toBe(true);
      expect(new Uint8Array(await readFile(target))).toEqual(DATA);
      expect((await stat(target)).mode & 0o777).toBe(0o640);
      expect(await readdir(shared)).toEqual(['doc.lineage']);
    });

    it('replaces the symlink itself when not following symlinks', async () => {
      const target = path.join(directory, 'target');
      await writeFile(target, 'old');
      await symlink(target, file);
      await writeFileDurably(file, DATA, { ...replace, followSymlinks: false });
      expect((await lstat(file)).isSymbolicLink()).toBe(false);
      expect(await readFile(target, 'utf8')).toEqual('old');
    });

    it('fails on a symlink loop', async () => {
      await symlink('doc.lineage', file);
      await expect(writeFileDurably(file, DATA, replace)).rejects.toMatchObject({ code: 'ELOOP', path: file });
    });
  });

  it('syncs the directory the file ends up in, and gets by where it cannot', async () => {
    const synced: string[] = [];
    const recording: IDurableFileSystem = {
      ...NODE_FILE_SYSTEM,
      syncDirectory: (dir) => {
        synced.push(dir);
        return Promise.reject(errno('EISDIR'));
      },
    };
    await writeFileDurably(file, DATA, { followSymlinks: false, publish: 'create' }, recording);
    expect(synced).toEqual([directory]);
    expect(new Uint8Array(await readFile(file))).toEqual(DATA);
  });
});
