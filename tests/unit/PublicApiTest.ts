import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const PACKAGE_NAME = '@unicitylabs/proof-cli';
/** Subpath in the `exports` map to the built file it resolves to. */
const ENTRY_POINTS = {
  '.': 'lib/index.js',
  './verify': 'lib/verify.js',
} as const;
/** Trailing slash so the prefix test cannot match a sibling directory. */
const PACKAGE_ROOT = pathToFileURL(`${path.resolve('.')}/`).href;

/**
 * Names `@unicitylabs/proof-cli/verify` publishes. Every one of them works with no
 * gateway, no API key and no filesystem; adding anything else to this list is a
 * claim that the name belongs in a browser.
 */
const VERIFY_EXPORTS: readonly string[] = [
  'NETWORKS',
  'NETWORK_NAMES',
  'PAYLOAD_VERSION',
  'TIMESTAMP_TAG',
  'TIMESTAMP_TOKEN_TYPE',
  'TIMESTAMP_TOKEN_TYPE_HEX',
  'TimestampIssuanceVerifier',
  'TimestampPayload',
  'TimestampPayloadError',
  'bundledTrustBase',
  'createVerificationContext',
  'decodePayload',
  'describeToken',
  'isNetworkName',
  'networkNameForId',
  'verificationFailure',
  'verify',
];

/** What the package root adds on top of {@link VERIFY_EXPORTS}: stamping needs a gateway. */
const STAMPING_EXPORTS: readonly string[] = [
  'DEFAULT_TIMEOUT_MS',
  'StampError',
  'TIMESTAMP_RECIPIENT',
  'resolveNetwork',
  'stamp',
  'stampWith',
];

const VERIFY_TYPE_EXPORTS: readonly string[] = [
  'DecodedPayload',
  'INetworkPreset',
  'ITimestampDescription',
  'ITimestampVerificationResult',
  'ITimestampVerifyOptions',
  'NetworkName',
];

const STAMPING_TYPE_EXPORTS: readonly string[] = [
  'ICertifyOptions',
  'INetworkOverrides',
  'IStampOptions',
  'ITimestampNetwork',
];

interface IModuleGraph {
  /** Node builtin specifier to the modules importing it. */
  readonly builtins: Map<string, string[]>;
  /** Every module reachable from the entry point, as a file URL. */
  readonly modules: Set<string>;
}

/** `import x from 'y'` and `export { x } from 'y'`, across line breaks. */
const REEXPORT = /(?:^|[\s;}])(?:import|export)[\s\S]*?from\s*['"]([^'"]+)['"]/g;
/** Side-effect imports and dynamic ones, which carry no `from`. */
const DIRECT_IMPORT = /(?:^|[\s;}])import\s*(?:\(\s*)?['"]([^'"]+)['"]/g;

/**
 * Walk a built entry point's module graph the way a bundler would, recording what
 * it reaches and every Node builtin it imports on the way.
 *
 * Resolution uses the Node condition, so a dependency shipping separate Node and
 * browser builds is seen through its Node build — the pessimistic choice.
 *
 * @param {string} entry Path to a built module.
 * @returns {Promise<IModuleGraph>} Reachable modules and the builtins they import.
 */
async function moduleGraph(entry: string): Promise<IModuleGraph> {
  const builtins = new Map<string, string[]>();
  const modules = new Set<string>();

  async function walk(url: string): Promise<void> {
    if (modules.has(url) || !url.endsWith('.js')) {
      return;
    }
    modules.add(url);
    const source = await readFile(new URL(url), 'utf8');
    const specifiers = [...source.matchAll(REEXPORT), ...source.matchAll(DIRECT_IMPORT)].map((match) => match[1]);
    for (const specifier of new Set(specifiers)) {
      if (specifier.startsWith('node:')) {
        builtins.set(specifier, [...(builtins.get(specifier) ?? []), url]);
        continue;
      }
      await walk(
        specifier.startsWith('.')
          ? new URL(specifier, url).href
          : pathToFileURL(createRequire(url).resolve(specifier)).href,
      );
    }
  }

  await walk(pathToFileURL(path.resolve(entry)).href);
  return { builtins, modules };
}

/** True for modules written in this repository, as opposed to dependencies. */
function isOwnModule(url: string): boolean {
  return url.startsWith(PACKAGE_ROOT) && !url.includes('/node_modules/');
}

/**
 * Import a specifier in a child process and list its exports.
 *
 * The package is imported by name, which Node resolves through its own `exports`
 * map, so this sees exactly what a consumer sees. Jest's CJS runtime cannot import
 * the built ESM directly, hence the child.
 *
 * @param {string} specifier Module specifier to import.
 * @returns {Promise<string[]>} Exported names, sorted.
 */
async function publishedExports(specifier: string): Promise<string[]> {
  const { stdout } = await execFileAsync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `const module = await import(${JSON.stringify(specifier)});
       console.log(JSON.stringify(Object.keys(module).sort()));`,
    ],
    { cwd: path.resolve('.') },
  );
  return JSON.parse(stdout) as string[];
}

function exportedTypes(source: string): string[] {
  return [...source.matchAll(/export type \{([^}]*)\}/g)]
    .flatMap((match) => match[1].split(','))
    .map((name) => name.trim())
    .filter((name) => name !== '')
    .sort();
}

describe('public library surface', () => {
  it('publishes exactly the offline names from /verify', async () => {
    expect(await publishedExports(`${PACKAGE_NAME}/verify`)).toEqual([...VERIFY_EXPORTS].sort());
  });

  it('publishes verification plus stamping from the package root', async () => {
    expect(await publishedExports(PACKAGE_NAME)).toEqual([...VERIFY_EXPORTS, ...STAMPING_EXPORTS].sort());
  });

  it('pins the exported types of both entry points', async () => {
    expect(exportedTypes(await readFile(path.resolve('src/verify.ts'), 'utf8'))).toEqual(
      [...VERIFY_TYPE_EXPORTS].sort(),
    );
    expect(exportedTypes(await readFile(path.resolve('src/index.ts'), 'utf8'))).toEqual(
      [...STAMPING_TYPE_EXPORTS].sort(),
    );
  });

  it('lists every public name instead of re-exporting modules wholesale', async () => {
    const verifySource = await readFile(path.resolve('src/verify.ts'), 'utf8');
    const indexSource = await readFile(path.resolve('src/index.ts'), 'utf8');
    expect(verifySource).not.toMatch(/export \*/);
    expect([...indexSource.matchAll(/export \* from '([^']+)'/g)].map((match) => match[1])).toEqual(['./verify.js']);
  });

  it('blocks deep imports, so the entry points are the whole surface', async () => {
    await expect(publishedExports(`${PACKAGE_NAME}/lib/lib/networks.js`)).rejects.toThrow(
      /ERR_PACKAGE_PATH_NOT_EXPORTED/,
    );
  });

  it('ships both entry points with their declarations', async () => {
    const manifest = JSON.parse(await readFile(path.resolve('package.json'), 'utf8')) as {
      exports: Record<string, { default: string; types: string }>;
      files: string[];
    };
    expect(Object.keys(manifest.exports).sort()).toEqual(Object.keys(ENTRY_POINTS).sort());
    expect(manifest.files).toContain('lib/**/*');
    for (const [subpath, built] of Object.entries(ENTRY_POINTS)) {
      expect(manifest.exports[subpath].default).toEqual(`./${built}`);
      expect(manifest.exports[subpath].types).toEqual(`./${built.replace(/\.js$/, '.d.ts')}`);
      await expect(readFile(path.resolve(built), 'utf8')).resolves.toContain('export');
      await expect(readFile(path.resolve(built.replace(/\.js$/, '.d.ts')), 'utf8')).resolves.toContain('export');
    }
  });

  it('keeps the gateway and the filesystem out of /verify', async () => {
    const graph = await moduleGraph(ENTRY_POINTS['./verify']);
    // Guards the guard: a regex that matched nothing would make every assertion
    // below pass on an empty graph.
    expect([...graph.modules].some((url) => url.includes('RootTrustBase'))).toBe(true);
    expect([...graph.builtins.keys()]).toEqual([]);
    expect([...graph.modules].filter((url) => /AggregatorClient|JsonRpc|\/uuid\//.test(url))).toEqual([]);
  });

  it('imports no Node builtin from any module in this package', async () => {
    const graph = await moduleGraph(ENTRY_POINTS['.']);
    expect([...graph.modules].filter(isOwnModule).length).toBeGreaterThan(5);
    expect(
      [...graph.builtins].flatMap(([builtin, importers]) =>
        importers.filter(isOwnModule).map((url) => `${builtin} <- ${url.slice(PACKAGE_ROOT.length)}`),
      ),
    ).toEqual([]);
  });
});
