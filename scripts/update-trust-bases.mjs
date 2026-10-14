// Refresh the bundled trust bases from unicitynetwork/unicity-ids and rewrite SOURCES.md.
// Usage: node scripts/update-trust-bases.mjs [--commit <sha>]
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPOSITORY = 'unicitynetwork/unicity-ids';
const NETWORKS = [
  { file: 'bft-trustbase.mainnet.json', name: 'mainnet' },
  { file: 'bft-trustbase.testnet2.json', name: 'testnet2' },
];

const targetDirectory = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'src', 'trust-bases');

async function fetchText(url) {
  const response = await fetch(url, { headers: { 'User-Agent': 'unicity-proof-cli' } });
  if (!response.ok) {
    throw new Error(`GET ${url} failed with HTTP ${response.status}`);
  }
  return response.text();
}

async function resolveCommit() {
  const index = process.argv.indexOf('--commit');
  if (index !== -1 && process.argv[index + 1]) {
    return process.argv[index + 1];
  }
  const body = JSON.parse(await fetchText(`https://api.github.com/repos/${REPOSITORY}/commits/main`));
  return body.sha;
}

const commit = await resolveCommit();
await mkdir(targetDirectory, { recursive: true });

const rows = [];
for (const network of NETWORKS) {
  const text = await fetchText(`https://raw.githubusercontent.com/${REPOSITORY}/${commit}/${network.file}`);
  const parsed = JSON.parse(text);
  if (typeof parsed.networkId !== 'number') {
    throw new Error(`${network.file} has no numeric networkId`);
  }
  await writeFile(path.join(targetDirectory, network.file), text);
  const digest = createHash('sha256').update(text).digest('hex');
  rows.push(`| ${network.file} | ${parsed.networkId} | ${digest} |`);
  console.error(`${network.name}: networkId ${parsed.networkId}, epoch ${parsed.epoch}, sha256 ${digest}`);
}

const sources = `# Bundled trust bases

Pinned copies of the Unicity consensus trust bases. They are the root of trust for offline verification and are never downloaded at run time. Refresh with \`npm run trust-bases:update\` and review the diff.

Source repository: https://github.com/${REPOSITORY}
Commit: ${commit}

| File | Network id | SHA-256 |
| --- | --- | --- |
${rows.join('\n')}
`;
await writeFile(path.join(targetDirectory, 'SOURCES.md'), sources);
console.error(`SOURCES.md updated at commit ${commit}`);
