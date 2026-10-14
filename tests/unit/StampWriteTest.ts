import { chmod, mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { writeCertifiedToken } from '../../src/commands/stamp.js';
import { testContext } from '../support/context.js';
import { tempDir } from '../support/fixtures.js';

const TOKEN = new Uint8Array([0xd9, 0x01, 0x00, 0x82, 0x01, 0x02]);

// By the time this runs the stamp has been certified and billed, and the bytes
// exist nowhere else. Every failure path therefore has to hand them back.
describe('writeCertifiedToken', () => {
  let directory: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-write-');
  });

  it('writes the token and nothing else', async () => {
    const out = path.join(directory, 'token.cbor');
    const sink = testContext();
    await writeCertifiedToken(out, TOKEN, false, sink.context);
    expect(new Uint8Array(await readFile(out))).toEqual(TOKEN);
    expect(await readdir(directory)).toEqual(['token.cbor']);
    expect(sink.stderr()).toEqual('');
  });

  it('refuses to clobber without --force, and prints the token so it is not lost', async () => {
    const out = path.join(directory, 'token.cbor');
    await writeFile(out, 'existing');
    const sink = testContext();

    await expect(writeCertifiedToken(out, TOKEN, false, sink.context)).rejects.toThrow(/EEXIST/);

    // The pre-existing file is untouched, the certified bytes are recoverable
    // from stderr, and no partial file is left lying around.
    expect(await readFile(out, 'utf8')).toEqual('existing');
    expect(sink.stderr()).toContain('could not be written');
    // The hint is the only instruction a user gets for recovering a stamp they
    // have already paid for, so it has to name a command that exists.
    expect(sink.stderr()).toContain('`unicity-proof verify` accepts hex text');
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
    expect(await readdir(directory)).toEqual(['token.cbor']);
  });

  it('replaces an existing file with --force', async () => {
    const out = path.join(directory, 'token.cbor');
    await writeFile(out, 'existing');
    const sink = testContext();
    await writeCertifiedToken(out, TOKEN, true, sink.context);
    expect(new Uint8Array(await readFile(out))).toEqual(TOKEN);
    expect(await readdir(directory)).toEqual(['token.cbor']);
    expect(sink.stderr()).toEqual('');
  });

  it('prints the token when the directory does not exist', async () => {
    const out = path.join(directory, 'no', 'such', 'dir', 'token.cbor');
    const sink = testContext();
    await expect(writeCertifiedToken(out, TOKEN, false, sink.context)).rejects.toThrow(/ENOENT/);
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });

  // Distinct from the missing-directory case: a permission error is the one a
  // best-effort cleanup would itself have thrown on, swallowing the recovery.
  it('prints the token when the directory cannot be written to', async () => {
    if (process.getuid?.() === 0) {
      return; // root ignores the mode, so there is nothing to deny.
    }
    const locked = path.join(directory, 'locked');
    await mkdir(locked, { mode: 0o500 });
    try {
      const sink = testContext();
      await expect(writeCertifiedToken(path.join(locked, 'token.cbor'), TOKEN, false, sink.context)).rejects.toThrow(
        /EACCES/,
      );
      expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
    } finally {
      await chmod(locked, 0o700);
    }
  });
});
