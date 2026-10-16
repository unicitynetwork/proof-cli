import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { EXIT_INTERRUPTED, EXIT_NETWORK, EXIT_OK, EXIT_USAGE, EXIT_VERIFICATION_FAILED } from '../../src/errors.js';

const SKILL = path.resolve('skills/unicity-proof/SKILL.md');

describe('agent skill', () => {
  it('documents exactly the exit codes the CLI returns', async () => {
    const skill = await readFile(SKILL, 'utf8');
    const documented = [...skill.matchAll(/^\| `(\d+)` \|/gm)].map((match) => Number(match[1]));
    expect(documented).toEqual([EXIT_OK, EXIT_VERIFICATION_FAILED, EXIT_USAGE, EXIT_NETWORK, EXIT_INTERRUPTED]);
  });

  it('quotes gateway messages the CLI can actually print', async () => {
    const skill = await readFile(SKILL, 'utf8');
    const sources = `${await readFile(path.resolve('src/errors.ts'), 'utf8')}${await readFile(
      path.resolve('src/lib/errors.ts'),
      'utf8',
    )}`;
    const quoted = [...skill.matchAll(/`(Could not reach|Gateway |Aggregator )([^`]*)`/g)].map((match) =>
      `${match[1]}${match[2]}`.replace(/ \.\.\.$/, ''),
    );
    expect(quoted.length).toBeGreaterThan(0);
    for (const message of quoted) {
      expect(sources).toContain(message);
    }
  });

  it('ships inside the package', async () => {
    const manifest = JSON.parse(await readFile(path.resolve('package.json'), 'utf8')) as { files: string[] };
    expect(manifest.files).toContain('skills/**/*');
  });
});
