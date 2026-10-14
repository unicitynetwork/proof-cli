import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { NETWORK_NAMES, NETWORKS } from '../../src/lib/networks.js';

const DIRECTORY = path.resolve('src/trust-bases');

describe('bundled trust bases', () => {
  it('match the rows recorded in SOURCES.md', async () => {
    const sources = await readFile(path.join(DIRECTORY, 'SOURCES.md'), 'utf8');
    for (const name of NETWORK_NAMES) {
      const file = `bft-trustbase.${name}.json`;
      const digest = createHash('sha256')
        .update(await readFile(path.join(DIRECTORY, file)))
        .digest('hex');
      expect(sources).toContain(`| ${file} | ${NETWORKS[name].networkId} | ${digest} |`);
    }
  });
});
