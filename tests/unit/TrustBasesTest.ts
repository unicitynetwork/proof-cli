import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { NETWORK_NAMES, NETWORKS } from '../../src/lib/networks.js';

const DIRECTORY = path.resolve('src/trust-bases');

interface IRecordedSource {
  readonly digest: string;
  readonly networkId: number;
}

/**
 * Read the table `scripts/update-trust-bases.mjs` writes into SOURCES.md.
 *
 * | bft-trustbase.mainnet.json | 1 | <sha256> |
 */
async function recordedSources(): Promise<Map<string, IRecordedSource>> {
  const text = await readFile(path.join(DIRECTORY, 'SOURCES.md'), 'utf8');
  const rows = new Map<string, IRecordedSource>();
  for (const line of text.split('\n')) {
    const match = /^\|\s*(bft-trustbase\.[\w.]+\.json)\s*\|\s*(\d+)\s*\|\s*([0-9a-f]{64})\s*\|$/.exec(line.trim());
    if (match) {
      rows.set(match[1], { digest: match[3], networkId: Number(match[2]) });
    }
  }
  return rows;
}

// The bundled trust bases are the root of trust for every offline verification,
// and SOURCES.md is the only record of what they are supposed to be. Nothing
// re-derived those digests, so swapping in attacker root nodes — keeping the
// networkId, which is all the other tests look at — passed the whole suite
// unchanged. This is the test that makes the pins mean something.
describe('bundled trust bases', () => {
  it('match the digests recorded in SOURCES.md', async () => {
    const recorded = await recordedSources();
    expect(recorded.size).toBe(NETWORK_NAMES.length);

    for (const name of NETWORK_NAMES) {
      const file = `bft-trustbase.${name}.json`;
      const source = recorded.get(file);
      expect(source).toBeDefined();

      const bytes = await readFile(path.join(DIRECTORY, file));
      const digest = createHash('sha256').update(bytes).digest('hex');
      expect({ digest, file }).toEqual({ digest: source!.digest, file });
    }
  });

  it('carry the network id the presets claim, and SOURCES.md agrees', async () => {
    const recorded = await recordedSources();
    for (const name of NETWORK_NAMES) {
      const parsed = JSON.parse(await readFile(path.join(DIRECTORY, `bft-trustbase.${name}.json`), 'utf8')) as {
        networkId: number;
      };
      expect({ id: parsed.networkId, name }).toEqual({ id: NETWORKS[name].networkId, name });
      expect(recorded.get(`bft-trustbase.${name}.json`)?.networkId).toBe(NETWORKS[name].networkId);
    }
  });

  it('are the files the build actually ships', async () => {
    // tsc re-serialises imported JSON into lib/, so the emitted copy is compared
    // by content rather than by bytes: a formatting difference is fine, a
    // different root of trust is not.
    for (const name of NETWORK_NAMES) {
      const source = JSON.parse(await readFile(path.join(DIRECTORY, `bft-trustbase.${name}.json`), 'utf8')) as unknown;
      const emitted = JSON.parse(
        await readFile(path.resolve('lib/trust-bases', `bft-trustbase.${name}.json`), 'utf8'),
      ) as unknown;
      expect({ name, trustBase: emitted }).toEqual({ name, trustBase: source });
    }
  });
});
