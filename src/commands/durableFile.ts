import { randomBytes } from 'node:crypto';
import { chmod, link, lstat, open, readlink, rename, rm, stat } from 'node:fs/promises';
import path from 'node:path';

/** A file just created by {@link IDurableFileSystem.openNew}. */
export interface IWritableFile {
  close(): Promise<void>;
  sync(): Promise<void>;
  writeFile(data: Uint8Array): Promise<void>;
}

/**
 * The file operations {@link writeFileDurably} needs, so tests can make one fail
 * partway. Each is the plain `node:fs/promises` call. Deciding what a failure
 * leaves behind is not their job: that stays in this module, where it is tested.
 */
export interface IDurableFileSystem {
  chmod(file: string, mode: number): Promise<void>;
  link(existing: string, file: string): Promise<void>;
  lstat(file: string): Promise<{ isSymbolicLink(): boolean }>;
  /** Create `file` exclusively (`wx`) with `mode`, subject to the umask, and open it for writing. */
  openNew(file: string, mode: number): Promise<IWritableFile>;
  readlink(file: string): Promise<string>;
  rename(from: string, to: string): Promise<void>;
  rm(file: string, options: { force: boolean }): Promise<void>;
  stat(file: string): Promise<{ mode: number }>;
  /** Flush a directory's entries; may fail where directories cannot be opened. */
  syncDirectory(directory: string): Promise<void>;
}

export const NODE_FILE_SYSTEM: IDurableFileSystem = {
  chmod,
  link,
  lstat,
  openNew: (file, mode) => open(file, 'wx', mode),
  readlink,
  rename,
  rm,
  stat,
  syncDirectory: async (directory) => {
    const handle = await open(directory, 'r');
    try {
      await handle.sync();
    } finally {
      await handle.close();
    }
  },
};

export interface IDurableWriteOptions {
  /**
   * Set the file to exactly this mode. Without it, a replaced file keeps its
   * mode, and a created one gets the default `0666` less the umask.
   */
  readonly fileMode?: number;
  /**
   * Write to the file at the end of a symlink chain at `file`, rather than
   * replacing or refusing the symlink itself. The symlink stays.
   */
  readonly followSymlinks: boolean;
  /**
   * `create`: refuse with EEXIST if anything is at the path, even a symlink to a
   * missing file, unless `followSymlinks`. `createInPlace`: the same, but written
   * directly under its name with no temporary: a crash during the write can leave
   * a partial file there, but never a second copy anywhere else. `replace`:
   * replace whatever is there.
   */
  readonly publish: 'create' | 'createInPlace' | 'replace';
}

/** Codes from `link` on a filesystem without hard links. */
const NO_HARD_LINKS = new Set(['ENOSYS', 'ENOTSUP', 'EOPNOTSUPP', 'EPERM']);

const MAX_SYMLINK_HOPS = 40;

function errorCode(error: unknown): unknown {
  // Not `instanceof Error`: errors from Node's fs need not come from this realm's Error.
  return typeof error === 'object' && error !== null ? (error as NodeJS.ErrnoException).code : undefined;
}

function fsError(code: string, message: string, file: string, cause?: unknown): NodeJS.ErrnoException {
  return Object.assign(new Error(`${code}: ${message}, '${file}'`, { cause }), { code, path: file });
}

/**
 * @param {IDurableFileSystem} fs File operations.
 * @param {string} file Starting path.
 * @returns {Promise<string>} The path at the end of the symlink chain at `file`; it need not exist.
 */
async function resolveSymlinks(fs: IDurableFileSystem, file: string): Promise<string> {
  let current = file;
  for (let hop = 0; hop < MAX_SYMLINK_HOPS; hop += 1) {
    const isLink = await fs.lstat(current).then(
      (stats) => stats.isSymbolicLink(),
      (error: unknown) => {
        if (errorCode(error) === 'ENOENT') {
          return false;
        }
        throw error;
      },
    );
    if (!isLink) {
      return current;
    }
    current = path.resolve(path.dirname(current), await fs.readlink(current));
  }
  throw fsError('ELOOP', 'too many symbolic links encountered', file);
}

/**
 * Write a file so that its name never refers to a partial file, even if the
 * process dies midway, and so that the result survives a power loss once this
 * returns.
 *
 * The data goes to a fresh sibling `.<name>.<random>`, created at 0600 when
 * its final mode is to be set, so it is never readable more widely on the way.
 * It is written and fsynced, then published: `create` links it in place, which
 * is atomic and refuses an existing name as an exclusive create does; `replace`
 * renames it over the old file. Then the directory is fsynced, where the
 * platform allows. The temporary is removed whatever happens.
 *
 * Where the filesystem has no hard links, `create` falls back to an exclusive
 * create of the name itself, and removes it again if a step after the create
 * fails; a failed create removes nothing. Only a
 * crash during that write can then leave a partial file. `createInPlace` always
 * works that way, for data of which a stray second copy would be worse than a
 * partial file.
 *
 * @param {string} file Absolute path.
 * @param {Uint8Array} data Contents.
 * @param {IDurableWriteOptions} options How to publish.
 * @param {IDurableFileSystem} [fs] File operations.
 * @throws {NodeJS.ErrnoException} EEXIST, carrying `file` as its path, when `create` finds the name taken.
 */
export async function writeFileDurably(
  file: string,
  data: Uint8Array,
  options: IDurableWriteOptions,
  fs: IDurableFileSystem = NODE_FILE_SYSTEM,
): Promise<void> {
  const target = options.followSymlinks ? await resolveSymlinks(fs, file) : file;
  const directory = path.dirname(target);
  if (options.publish === 'createInPlace') {
    await createInPlace(fs, target, data, options.fileMode);
    await fs.syncDirectory(directory).catch(() => undefined);
    return;
  }
  let mode = options.fileMode;
  if (mode === undefined && options.publish === 'replace') {
    mode = await fs.stat(target).then(
      (stats) => stats.mode & 0o7777,
      () => undefined,
    );
  }
  const temporary = path.join(directory, `.${path.basename(target)}.${randomBytes(8).toString('hex')}`);
  try {
    await writeExclusive(fs, temporary, data, mode === undefined ? 0o666 : 0o600);
    if (mode !== undefined) {
      await fs.chmod(temporary, mode);
    }
    if (options.publish === 'replace') {
      await fs.rename(temporary, target);
    } else {
      await publishNew(fs, temporary, target, data, mode);
    }
  } finally {
    // Best effort, and never allowed to replace the error that actually matters.
    await fs.rm(temporary, { force: true }).catch(() => undefined);
  }
  await fs.syncDirectory(directory).catch(() => undefined);
}

async function publishNew(
  fs: IDurableFileSystem,
  temporary: string,
  target: string,
  data: Uint8Array,
  mode: number | undefined,
): Promise<void> {
  try {
    await fs.link(temporary, target);
    return;
  } catch (error) {
    if (errorCode(error) === 'EEXIST') {
      // `link` reports the temporary as the path; the name that was taken is the target.
      throw fsError('EEXIST', 'file already exists', target, error);
    }
    if (!NO_HARD_LINKS.has(errorCode(error) as string)) {
      throw error;
    }
  }
  await createInPlace(fs, target, data, mode);
}

/**
 * Create `file` exclusively, write `data`, fsync and close it. If anything after
 * the create fails, the file is removed again: this call made it. If the create
 * itself fails, nothing is removed, whatever the error. A failed open does not
 * mean the name was free: Linux allocates the descriptor before it looks up the
 * path, so EMFILE, ENFILE or ENOMEM come back even when the file exists, and it
 * may be someone's private key.
 *
 * @param {IDurableFileSystem} fs File operations.
 * @param {string} file Path to create.
 * @param {Uint8Array} data Contents.
 * @param {number} mode Mode to create it with, subject to the umask.
 * @throws {NodeJS.ErrnoException} EEXIST, carrying `file` as its path, when the name is taken.
 */
async function writeExclusive(fs: IDurableFileSystem, file: string, data: Uint8Array, mode: number): Promise<void> {
  let handle: IWritableFile;
  try {
    handle = await fs.openNew(file, mode);
  } catch (error) {
    if (errorCode(error) === 'EEXIST') {
      throw fsError('EEXIST', 'file already exists', file, error);
    }
    throw error;
  }
  let failure: { error: unknown } | null = null;
  try {
    await handle.writeFile(data);
    await handle.sync();
  } catch (error) {
    failure = { error };
  }
  try {
    await handle.close();
  } catch (error) {
    failure ??= { error };
  }
  if (failure !== null) {
    // Best effort, and never allowed to replace the error that actually matters.
    await fs.rm(file, { force: true }).catch(() => undefined);
    throw failure.error;
  }
}

/**
 * An exclusive create of the name itself, written, fsynced and set to `mode`. A
 * file this call created is removed again if a later step fails; nothing else is
 * ever removed.
 *
 * @param {IDurableFileSystem} fs File operations.
 * @param {string} target Path to create.
 * @param {Uint8Array} data Contents.
 * @param {number|undefined} mode Exact mode, or undefined for the default less the umask.
 */
async function createInPlace(
  fs: IDurableFileSystem,
  target: string,
  data: Uint8Array,
  mode: number | undefined,
): Promise<void> {
  await writeExclusive(fs, target, data, mode === undefined ? 0o666 : 0o600);
  if (mode === undefined) {
    return;
  }
  try {
    await fs.chmod(target, mode);
  } catch (error) {
    // The create succeeded, so the file is this call's.
    await fs.rm(target, { force: true }).catch(() => undefined);
    throw error;
  }
}
