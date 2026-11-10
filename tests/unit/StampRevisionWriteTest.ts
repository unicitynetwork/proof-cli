import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { writeRevisionToken } from '../../src/commands/stampRevision.js';
import { testContext } from '../support/context.js';
import { tempDir } from '../support/fixtures.js';

describe('writeRevisionToken', () => {
  const TOKEN = new Uint8Array([0xd9, 0x01, 0x00, 0x82, 0x01, 0x02]);

  it('replaces an existing file without leaving a temporary behind', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    await writeFile(out, 'old');
    const sink = testContext();
    await writeRevisionToken(out, TOKEN, false, sink.context);
    expect(new Uint8Array(await readFile(out))).toEqual(TOKEN);
    expect(await readdir(directory)).toEqual(['doc.lineage']);
    expect(sink.stderr()).toEqual('');
  });

  it('never clobbers a file that appeared before a new lineage was written, and prints the token', async () => {
    const directory = await tempDir('proof-cli-revision-');
    const out = path.join(directory, 'doc.lineage');
    await writeFile(out, 'someone else');
    const sink = testContext();
    await expect(writeRevisionToken(out, TOKEN, true, sink.context)).rejects.toThrow(/EEXIST/);
    expect(await readFile(out, 'utf8')).toEqual('someone else');
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });

  it('prints the token when the directory is gone', async () => {
    const directory = await tempDir('proof-cli-revision-');
    await mkdir(path.join(directory, 'sub'));
    const sink = testContext();
    await expect(
      writeRevisionToken(path.join(directory, 'missing', 'doc.lineage'), TOKEN, false, sink.context),
    ).rejects.toThrow(/ENOENT/);
    expect(sink.stderr()).toContain('the revision was certified');
    expect(sink.stderr()).toContain(HexConverter.encode(TOKEN));
  });
});
