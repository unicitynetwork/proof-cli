import { chmod, lstat, readdir, readFile, readlink, stat, symlink, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
  IDurableFileSystem,
  IWritableFile,
  NODE_FILE_SYSTEM,
  writeFileDurably,
} from '../../src/commands/durableFile.js';
import { tempDir } from '../support/fixtures.js';

const DATA = new TextEncoder().encode('new contents\n');

function errno(code: string): NodeJS.ErrnoException {
  return Object.assign(new Error(code), { code });
}

type Step = 'close' | 'sync' | 'writeFile';

/**
 * The real file system, with the file `fail` picks failing at `step` after it
 * was created: `writeFile` writes only the first three bytes before failing.
 */
function failingWrite(fail: (file: string) => boolean, step: Step = 'writeFile'): IDurableFileSystem {
  return {
    ...NODE_FILE_SYSTEM,
    openNew: async (file, mode): Promise<IWritableFile> => {
      const handle = await NODE_FILE_SYSTEM.openNew(file, mode);
      if (!fail(file)) {
        return handle;
      }
      const failure = errno(step === 'writeFile' ? 'ENOSPC' : 'EIO');
      async function close(): Promise<void> {
        await handle.close();
        if (step === 'close') {
          throw failure;
        }
      }
      async function sync(): Promise<void> {
        if (step === 'sync') {
          throw failure;
        }
        await handle.sync();
      }
      async function write(data: Uint8Array): Promise<void> {
        if (step !== 'writeFile') {
          await handle.writeFile(data);
          return;
        }
        await handle.writeFile(data.subarray(0, 3));
        throw failure;
      }
      return { close, sync, writeFile: write };
    },
  };
}

/** The real file system, with creating the file `fail` picks failing at the open itself, with `code`. */
function failingOpen(fail: (file: string) => boolean, code: string): IDurableFileSystem {
  return {
    ...NODE_FILE_SYSTEM,
    openNew: (file, mode): Promise<IWritableFile> =>
      fail(file) ? Promise.reject(errno(code)) : NODE_FILE_SYSTEM.openNew(file, mode),
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

  describe('createInPlace', () => {
    const inPlace = { fileMode: 0o600, followSymlinks: false, publish: 'createInPlace' } as const;

    it('writes under the name itself, with no temporary that a crash could leave behind', async () => {
      const created: string[] = [];
      const recording: IDurableFileSystem = {
        ...NODE_FILE_SYSTEM,
        link: noLink,
        openNew: (name, mode) => {
          created.push(name);
          return NODE_FILE_SYSTEM.openNew(name, mode);
        },
      };
      await writeFileDurably(file, DATA, inPlace, recording);
      expect(created).toEqual([file]);
      expect(new Uint8Array(await readFile(file))).toEqual(DATA);
      expect((await stat(file)).mode & 0o777).toBe(0o600);
    });

    it('refuses an existing file or symlink, and removes a partial file it created', async () => {
      await writeFile(file, 'someone else');
      await expect(writeFileDurably(file, DATA, inPlace)).rejects.toMatchObject({ code: 'EEXIST', path: file });
      expect(await readFile(file, 'utf8')).toEqual('someone else');

      const link = path.join(directory, 'link');
      await symlink(path.join(directory, 'missing'), link);
      await expect(writeFileDurably(link, DATA, inPlace)).rejects.toMatchObject({ code: 'EEXIST', path: link });

      const other = path.join(directory, 'other.key');
      await expect(
        writeFileDurably(
          other,
          DATA,
          inPlace,
          failingWrite(() => true),
        ),
      ).rejects.toMatchObject({
        code: 'ENOSPC',
      });
      expect((await readdir(directory)).sort()).toEqual(['doc.lineage', 'link']);
    });
  });

  // MastaP on PR #16: a failed open is not proof the name was free. Linux allocates the
  // descriptor before it looks up the path, so EMFILE comes back even when the file exists.
  describe('a create that fails at the open', () => {
    it.each(['EMFILE', 'ENFILE', 'ENOMEM'])('never removes an existing file, written in place (%s)', async (code) => {
      await writeFile(file, 'existing key\n', { mode: 0o600 });
      await expect(
        writeFileDurably(
          file,
          DATA,
          { fileMode: 0o600, followSymlinks: false, publish: 'createInPlace' },
          failingOpen(() => true, code),
        ),
      ).rejects.toMatchObject({ code });
      expect(await readFile(file, 'utf8')).toEqual('existing key\n');
    });

    it('never removes an existing file on the no-hard-link fallback either', async () => {
      await writeFile(file, 'existing token');
      const fs = { ...failingOpen((name) => name === file, 'EMFILE'), link: noLink };
      await expect(
        writeFileDurably(file, DATA, { followSymlinks: false, publish: 'create' }, fs),
      ).rejects.toMatchObject({ code: 'EMFILE' });
      expect(await readFile(file, 'utf8')).toEqual('existing token');
      expect(await readdir(directory)).toEqual(['doc.lineage']);
    });
  });

  describe('a create that fails after the open', () => {
    const inPlace = { fileMode: 0o600, followSymlinks: false, publish: 'createInPlace' } as const;

    it.each<Step>(['writeFile', 'sync', 'close'])('removes the file it created (%s fails)', async (step) => {
      await expect(
        writeFileDurably(
          file,
          DATA,
          inPlace,
          failingWrite(() => true, step),
        ),
      ).rejects.toHaveProperty('code');
      expect(await readdir(directory)).toEqual([]);
    });

    it('removes the file it created when setting its mode fails', async () => {
      const fs = { ...NODE_FILE_SYSTEM, chmod: (): Promise<void> => Promise.reject(errno('EPERM')) };
      await expect(writeFileDurably(file, DATA, inPlace, fs)).rejects.toMatchObject({ code: 'EPERM' });
      expect(await readdir(directory)).toEqual([]);
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

    it('replaces the file only while it still holds what the caller started from', async () => {
      await writeFile(file, 'old');
      const old = new TextEncoder().encode('old');
      await writeFile(file, 'newer, by someone else');
      await expect(writeFileDurably(file, DATA, { ...replace, ifUnchanged: old })).rejects.toMatchObject({
        code: 'ECHANGED',
        path: file,
      });
      expect(await readFile(file, 'utf8')).toEqual('newer, by someone else');
      expect(await readdir(directory)).toEqual(['doc.lineage']);

      await writeFile(file, 'old');
      await writeFileDurably(file, DATA, { ...replace, ifUnchanged: old });
      expect(new Uint8Array(await readFile(file))).toEqual(DATA);
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
