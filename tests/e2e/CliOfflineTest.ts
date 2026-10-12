import { chmod, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { runCli } from '../support/cli.js';
import { tempDir, TEST_DIGEST_HEX } from '../support/fixtures.js';

const TIMEOUT = 30_000;

describe('unicity-timestamp (offline)', () => {
  let cwd: string;

  beforeAll(async () => {
    cwd = await tempDir('timestamp-cli-e2e-');
  });

  it(
    'prints help and version',
    async () => {
      const [help, version] = await Promise.all([runCli(['--help'], { cwd }), runCli(['--version'], { cwd })]);
      expect(help.code).toBe(0);
      expect(help.stdout).toContain('stamp');
      expect(help.stdout).toContain('verify');
      expect(version.code).toBe(0);
      // Read from the manifest rather than written out, so a release bump does
      // not have to remember to come back and edit this line.
      const manifest = JSON.parse(await readFile(path.resolve('package.json'), 'utf8')) as { version: string };
      expect(version.stdout.trim()).toEqual(manifest.version);
    },
    TIMEOUT,
  );

  it(
    'exits 2 on usage errors before touching the network',
    async () => {
      const cases: string[][] = [
        ['stamp', 'not-a-digest', '--api-key', 'sk_x'],
        ['stamp', TEST_DIGEST_HEX, '--file', 'x', '--api-key', 'sk_x'],
        ['stamp', '--api-key', 'sk_x'],
        ['stamp', TEST_DIGEST_HEX],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--sign'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--network', 'devnet'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--gateway', 'http://127.0.0.1:9'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--timeout', '0'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--timeout', '2147484'],
        // A mistyped --out directory is the realistic way to reach a write failure
        // after the stamp has been billed, so it has to be caught here instead.
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--out', '/nonexistent-dir-xyzzy/token.cbor'],
        ['verify', '/nonexistent.cbor'],
        ['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x', '--dotenv', '/nonexistent.env'],
        ['nonsense'],
      ];
      const results = await Promise.all(cases.map((args) => runCli(args, { cwd })));
      results.forEach((result, index) => {
        expect({ args: cases[index], code: result.code }).toEqual({ args: cases[index], code: 2 });
        expect(result.stderr).not.toEqual('');
      });
    },
    TIMEOUT,
  );

  it(
    'loads env files but lets the environment win',
    async () => {
      const envFile = path.join(cwd, 'custom.env');
      await writeFile(envFile, 'UNICITY_NETWORK=devnet\n');
      const dotenvDir = await tempDir('timestamp-cli-dotenv-');
      await writeFile(path.join(dotenvDir, '.env'), 'UNICITY_NETWORK=devnet\n');
      const args = [
        'stamp',
        TEST_DIGEST_HEX,
        '--api-key',
        'sk_x',
        '--gateway',
        'http://127.0.0.1:9',
        '--dotenv',
        envFile,
      ];

      const [fromFile, fromEnv, fromDefault] = await Promise.all([
        runCli(args, { cwd }),
        runCli(args, { cwd, env: { UNICITY_NETWORK: 'testnet2' } }),
        runCli(['stamp', TEST_DIGEST_HEX, '--api-key', 'sk_x'], { cwd: dotenvDir }),
      ]);
      expect(fromFile.code).toBe(2);
      expect(fromFile.stderr).toContain("Unknown network 'devnet'");
      expect(fromEnv.code).toBe(2);
      expect(fromEnv.stderr).toContain('plain HTTP');
      expect(fromDefault.code).toBe(2);
      expect(fromDefault.stderr).toContain("Unknown network 'devnet'");
    },
    TIMEOUT,
  );

  it(
    'reports files that are not tokens with exit 1',
    async () => {
      const garbage = path.join(cwd, 'garbage.cbor');
      await writeFile(garbage, 'definitely not cbor');
      const [verify, fromStdin, inspect] = await Promise.all([
        runCli(['verify', garbage], { cwd }),
        runCli(['verify', '-', '--json'], { cwd, input: 'deadbeef' }),
        runCli(['inspect', garbage], { cwd }),
      ]);
      expect(verify.code).toBe(1);
      expect(verify.stdout).toContain('FAIL: not a token');
      expect(fromStdin.code).toBe(1);
      expect(JSON.parse(fromStdin.stdout)).toMatchObject({ command: 'verify', status: 'FAIL' });
      expect(inspect.code).toBe(1);
    },
    TIMEOUT,
  );

  it(
    'generates keys with mode 0600 and refuses to overwrite',
    async () => {
      const keyFile = path.join(cwd, 'my.key');
      const first = await runCli(['keygen', '--out', keyFile], { cwd });
      expect(first.code).toBe(0);
      expect(first.stdout).toContain('Public key');
      const key = (await readFile(keyFile, 'utf8')).trim();
      expect(key).toMatch(/^[0-9a-f]{64}$/);
      expect((await stat(keyFile)).mode & 0o777).toBe(0o600);

      const second = await runCli(['keygen', '--out', keyFile], { cwd });
      expect(second.code).toBe(2);
      expect(second.stderr).toContain('Refusing to overwrite');

      const forced = await runCli(['keygen', '--out', keyFile, '--force', '--json'], { cwd });
      expect(forced.code).toBe(0);
      expect(JSON.parse(forced.stdout)).toMatchObject({ command: 'keygen', out: keyFile });
      expect((await readFile(keyFile, 'utf8')).trim()).not.toEqual(key);

      const piped = await runCli(['keygen', '--out', '-'], { cwd });
      expect(piped.code).toBe(0);
      expect(piped.stdout.trim()).toMatch(/^[0-9a-f]{64}$/);
      expect(piped.stderr).toEqual('');
    },
    TIMEOUT,
  );

  it(
    'writes a forced key to a new 0600 inode rather than into the old one',
    async () => {
      // `writeFile`'s mode applies only when a file is created, so overwriting in
      // place would fill the existing inode while it still carried the old
      // permissions. Narrowing it afterwards is not enough: a reader that opened
      // the file first keeps its descriptor across the change. The forced path has
      // to land on a different inode, which is what this asserts.
      const keyFile = path.join(cwd, 'loose.key');
      await writeFile(keyFile, 'placeholder\n', { mode: 0o600 });
      await chmod(keyFile, 0o644);
      const before = await stat(keyFile);
      expect(before.mode & 0o777).toBe(0o644);

      const forced = await runCli(['keygen', '--out', keyFile, '--force'], { cwd });
      expect(forced.code).toBe(0);
      expect(forced.stdout).toContain('mode 0600');

      const after = await stat(keyFile);
      expect(after.mode & 0o777).toBe(0o600);
      expect(after.ino).not.toEqual(before.ino);
      expect((await readFile(keyFile, 'utf8')).trim()).toMatch(/^[0-9a-f]{64}$/);

      // No staging file left in the directory.
      expect((await readdir(cwd)).filter((name) => name.startsWith('.loose.key.'))).toEqual([]);
    },
    TIMEOUT,
  );

  it(
    'ignores a trust base named by a .env found in the working directory',
    async () => {
      // A token plus a .env naming the trust base that validates it would
      // otherwise be a complete forgery kit, and the verdict would not say so.
      const directory = await tempDir('timestamp-cli-dotenv-');
      const mainnetTrustBase = path.resolve('src/trust-bases/bft-trustbase.mainnet.json');
      const fixture = path.resolve('tests/fixtures/testnet2-anonymous.cbor');
      await writeFile(path.join(directory, '.env'), `UNICITY_TRUST_BASE=${mainnetTrustBase}\n`);

      const ignored = await runCli(['verify', fixture, '--json'], { cwd: directory });
      expect(ignored.code).toBe(0);
      expect(JSON.parse(ignored.stdout)).toMatchObject({
        status: 'OK',
        trustBase: { bundledNetwork: 'testnet2', path: null, source: 'bundled' },
      });
      expect(ignored.stderr).toContain('ignored UNICITY_TRUST_BASE');

      // The same override, asked for explicitly, still applies — and the verdict
      // names the file rather than wearing the bundled pin's name.
      const explicit = await runCli(['verify', fixture, '--trust-base', mainnetTrustBase], { cwd: directory });
      expect(explicit.code).toBe(1);
      expect(explicit.stdout).toContain(mainnetTrustBase);
      expect(explicit.stdout).toContain('override, not the bundled pin');

      const viaDotenv = await runCli(['--dotenv', path.join(directory, '.env'), 'verify', fixture, '--json'], {
        cwd: directory,
      });
      expect(JSON.parse(viaDotenv.stdout)).toMatchObject({
        trustBase: { bundledNetwork: null, path: mainnetTrustBase, source: 'file' },
      });
    },
    TIMEOUT,
  );

  it(
    'verifies the committed fixtures offline',
    async () => {
      const fixtures = path.resolve('tests/fixtures');
      const anonymous = path.join(fixtures, 'testnet2-anonymous.cbor');
      const tampered = path.join(cwd, 'tampered.cbor');
      const bytes = new Uint8Array(await readFile(anonymous));
      bytes[bytes.length - 1] ^= 0x01;
      await writeFile(tampered, bytes);

      const [anonymousResult, signedResult, mismatch, wrongNetwork, tamperedResult, inspected] = await Promise.all([
        runCli(['verify', anonymous, '--json'], { cwd }),
        runCli(['verify', path.join(fixtures, 'testnet2-signed.cbor'), '--json'], { cwd }),
        runCli(['verify', anonymous, '--hash', TEST_DIGEST_HEX], { cwd }),
        runCli(['verify', anonymous, '--network', 'mainnet'], { cwd }),
        runCli(['verify', tampered], { cwd }),
        runCli(['inspect', anonymous, '--json'], { cwd }),
      ]);

      for (const [result, signed] of [
        [anonymousResult, false],
        [signedResult, true],
      ] as const) {
        expect(result.code).toBe(0);
        const json = JSON.parse(result.stdout) as { network: { name: string }; signer: string | null; status: string };
        expect(json.status).toEqual('OK');
        expect(json.network.name).toEqual('testnet2');
        expect(json.signer !== null).toBe(signed);
      }
      expect(mismatch.code).toBe(1);
      expect(mismatch.stdout).toContain('Hash mismatch');
      expect(wrongNetwork.code).toBe(1);
      expect(wrongNetwork.stdout).toContain('network 4 but the trust base is for network 1');
      expect(tamperedResult.code).toBe(1);
      expect(inspected.code).toBe(0);
      expect(JSON.parse(inspected.stdout)).toMatchObject({ command: 'inspect', network: { id: 4 }, verified: false });
    },
    TIMEOUT,
  );
});
