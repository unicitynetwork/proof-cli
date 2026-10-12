import { randomBytes } from 'node:crypto';
import { chmod, rename, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import { EXIT_OK } from '../errors.js';
import { keygenJson, keygenText, toJsonLine } from '../output.js';

export interface IKeygenFlags {
  readonly force?: boolean;
  readonly out?: string;
}

const DEFAULT_KEY_FILE = 'unicity-timestamp.key';

/**
 * Write a private key to a path that already holds a file.
 *
 * Overwriting in place would truncate and fill the existing inode, which keeps
 * whatever permissions it already had for the duration of the write: narrowing it
 * afterwards is too late, because a reader that opened the file beforehand keeps
 * its descriptor across the change, and a failed `chmod` would leave the finished
 * key exposed. The key therefore goes to a fresh inode that is 0600 from creation
 * and is moved into place with `rename`, which is atomic and never publishes the
 * secret through the old inode.
 *
 * This is the opposite choice from `writeCertifiedToken`, deliberately: there,
 * staging bought nothing and added ways to fail after a stamp had been billed,
 * whereas here it is the only way to never expose the key, and a failed `keygen`
 * costs nothing to repeat. `rename` also works on filesystems without hard links.
 *
 * @param {string} out Absolute destination path.
 * @param {string} contents Key file contents.
 */
async function replaceKeyFile(out: string, contents: string): Promise<void> {
  const temporary = path.join(path.dirname(out), `.${path.basename(out)}.${randomBytes(8).toString('hex')}`);
  try {
    await writeKeyFile(temporary, contents);
    await rename(temporary, out);
  } catch (error) {
    // Best effort, and never allowed to replace the error that actually matters.
    await rm(temporary, { force: true }).catch(() => undefined);
    throw error;
  }
}

/**
 * Create a new file holding a private key, at exactly mode 0600.
 *
 * `writeFile`'s `mode` is masked by the process umask, so a umask that happens to
 * cover owner bits yields 0200 or 0000 and leaves a key nothing can read, while
 * the summary still reports 0600. The explicit `chmod` corrects that. It cannot
 * widen the file past 0600 on the way, because a umask only ever removes bits —
 * which is what makes it safe here, unlike narrowing an inode that was already
 * public.
 *
 * @param {string} file Path to create; must not exist.
 * @param {string} contents Key file contents.
 */
async function writeKeyFile(file: string, contents: string): Promise<void> {
  await writeFile(file, contents, { flag: 'wx', mode: 0o600 });
  await chmod(file, 0o600);
}

/**
 * `keygen`: write a fresh secp256k1 private key as 64 hex characters, mode 0600.
 * An existing file is left alone unless `--force`; the EEXIST from `wx` is
 * rendered by the shared error mapping.
 *
 * @param {IKeygenFlags} flags Command flags.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code.
 */
export async function runKeygen(flags: IKeygenFlags, context: ICommandContext): Promise<number> {
  const privateKey = SigningService.generatePrivateKey();
  const hex = HexConverter.encode(privateKey);

  if (flags.out === '-') {
    context.stdout.write(`${hex}\n`);
    return EXIT_OK;
  }

  const out = path.resolve(flags.out ?? DEFAULT_KEY_FILE);
  if (flags.force) {
    await replaceKeyFile(out, `${hex}\n`);
  } else {
    // A fresh file is never wider than 0600, and `wx` is what refuses an existing
    // one, so this path needs no staging.
    await writeKeyFile(out, `${hex}\n`);
  }

  const publicKey = HexConverter.encode(new SigningService(privateKey).publicKey);
  context.stdout.write(context.json ? toJsonLine(keygenJson(out, publicKey)) : `${keygenText(out, publicKey)}\n`);
  return EXIT_OK;
}
