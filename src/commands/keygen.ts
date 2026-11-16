import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { ICommandContext } from './context.js';
import { writeFileDurably } from './durableFile.js';
import { EXIT_OK } from '../errors.js';
import { keygenJson, keygenText, toJsonLine } from '../output.js';

export interface IKeygenFlags {
  readonly force?: boolean;
  readonly out?: string;
}

const DEFAULT_KEY_FILE = 'unicity-proof.key';

/**
 * Write a private key file at exactly mode 0600, with {@link writeFileDurably}.
 *
 * The key goes to a fresh inode that is 0600 from creation and is moved into
 * place, never written into an existing file: overwriting in place would fill an
 * inode that keeps whatever permissions it already had for the duration of the
 * write, and narrowing it afterwards is too late, because a reader that opened it
 * beforehand keeps its descriptor. The explicit mode is also what corrects a
 * umask that covers owner bits, which would otherwise leave 0200 or 0000 while
 * the summary reports 0600; it cannot widen the file on the way, since a umask
 * only removes bits. A symlink at the path is replaced or refused, never written
 * through: a key is not written to wherever a link happens to point.
 *
 * Staging is the opposite choice from `writeCertifiedToken`, deliberately: there,
 * it bought nothing and added ways to fail after a stamp had been billed, whereas
 * here it is the only way to never expose the key, and a failed `keygen` costs
 * nothing to repeat.
 *
 * @param {string} out Absolute destination path.
 * @param {string} contents Key file contents.
 * @param {boolean} replace Whether an existing file may be replaced; otherwise EEXIST.
 */
async function writeKeyFile(out: string, contents: string, replace: boolean): Promise<void> {
  await writeFileDurably(out, new TextEncoder().encode(contents), {
    fileMode: 0o600,
    followSymlinks: false,
    publish: replace ? 'replace' : 'create',
  });
}

/**
 * `keygen`: write a fresh secp256k1 private key as 64 hex characters, mode 0600.
 * An existing file is left alone unless `--force`; the EEXIST is rendered by
 * the shared error mapping.
 *
 * @param {IKeygenFlags} flags Command flags.
 * @param {ICommandContext} context Streams.
 * @returns {Promise<number>} Exit code.
 */
export async function runKeygen(flags: IKeygenFlags, context: ICommandContext): Promise<number> {
  const privateKey = SigningService.generatePrivateKey();
  const hex = HexConverter.encode(privateKey);
  const publicKey = HexConverter.encode(new SigningService(privateKey).publicKey);

  if (flags.out === '-') {
    // The private key is in the JSON on this path only: stdout is where it was
    // asked to go. A file-bound keygen must not copy the secret back out of the
    // 0600 file and into whatever reads the output.
    context.stdout.write(context.json ? toJsonLine(keygenJson(null, publicKey, hex)) : `${hex}\n`);
    return EXIT_OK;
  }

  const out = path.resolve(flags.out ?? DEFAULT_KEY_FILE);
  await writeKeyFile(out, `${hex}\n`, flags.force ?? false);

  context.stdout.write(context.json ? toJsonLine(keygenJson(out, publicKey)) : `${keygenText(out, publicKey)}\n`);
  return EXIT_OK;
}
