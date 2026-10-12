// Rewrite src/version.ts from the version in package.json.
//
// The CLI reports its version from a compiled constant rather than by reading
// package.json at run time, so that it still works when the package is bundled.
// That means the number lives in two places, and this script is what keeps the
// second one honest. It runs from the `version` npm lifecycle script, which fires
// after `npm version` has rewritten the manifest and before it commits, so the
// regenerated file lands in the same commit as the bump.
//
// `tests/unit/VersionTest.ts` fails if the two ever disagree.
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));

if (typeof manifest.version !== 'string') {
  throw new Error('package.json has no version string.');
}

const target = path.join(root, 'src', 'version.ts');
const contents = `/** Kept in sync with package.json by \`npm run sync-version\`, and checked by a unit test. */
export const VERSION = '${manifest.version}';
`;

const previous = await readFile(target, 'utf8').catch(() => '');
if (previous === contents) {
  console.error(`src/version.ts already at ${manifest.version}`);
} else {
  await writeFile(target, contents);
  console.error(`src/version.ts set to ${manifest.version}`);
}
