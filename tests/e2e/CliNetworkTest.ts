import { copyFile, mkdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { runCli } from '../support/cli.js';
import { tempDir } from '../support/fixtures.js';

const TEST_API_KEY = process.env.UNICITY_TEST_API_KEY;
const TEST_NETWORK = process.env.UNICITY_TEST_NETWORK ?? 'testnet2';
const OTHER_NETWORK = TEST_NETWORK === 'mainnet' ? 'testnet2' : 'mainnet';
const TIMEOUT = 180_000;

const describeNetwork = TEST_API_KEY ? describe : describe.skip;
const itWritesFixtures = process.env.UNICITY_E2E_WRITE_FIXTURES === '1' ? it : it.skip;

describeNetwork(`unicity-proof against ${TEST_NETWORK}`, () => {
  let cwd: string;
  const env = { UNICITY_API_KEY: TEST_API_KEY ?? '', UNICITY_NETWORK: TEST_NETWORK };
  const digest = HexConverter.encode(crypto.getRandomValues(new Uint8Array(32)));
  const otherDigest = HexConverter.encode(crypto.getRandomValues(new Uint8Array(32)));
  let anonymousToken: string;
  let signedToken: string;

  beforeAll(async () => {
    cwd = await tempDir('proof-cli-net-');
    anonymousToken = path.join(cwd, 'anonymous.cbor');
    signedToken = path.join(cwd, 'signed.cbor');
  });

  it(
    'stamps a digest anonymously and writes the token',
    async () => {
      const result = await runCli(['stamp', digest, '--out', anonymousToken, '--json'], { cwd, env });
      expect(result.stderr).toEqual('');
      expect(result.code).toBe(0);
      const json = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(json).toMatchObject({
        command: 'stamp',
        hash: { algorithm: 'SHA-256', digest },
        network: { name: TEST_NETWORK },
        out: anonymousToken,
        signer: null,
      });
      expect(typeof json.referenceTime).toBe('string');
      expect((await stat(anonymousToken)).size).toBeGreaterThan(0);
      expect(HexConverter.encode(new Uint8Array(await readFile(anonymousToken)))).toEqual(json.token);
    },
    TIMEOUT,
  );

  it(
    'verifies the token offline, detecting the network from the token',
    async () => {
      const hexInput = HexConverter.encode(new Uint8Array(await readFile(anonymousToken)));
      const [plain, matching, mismatch, wrongNetwork, fromStdin, inspected] = await Promise.all([
        runCli(['verify', anonymousToken], { cwd }),
        runCli(['verify', anonymousToken, '--hash', digest, '--json'], { cwd }),
        runCli(['verify', anonymousToken, '--hash', otherDigest], { cwd }),
        runCli(['verify', anonymousToken, '--network', OTHER_NETWORK], { cwd }),
        runCli(['verify', '-'], { cwd, input: hexInput }),
        runCli(['inspect', anonymousToken], { cwd }),
      ]);
      expect(plain.code).toBe(0);
      expect(plain.stdout).toContain('Status         OK');
      expect(plain.stdout).toContain(`Hash           SHA-256 ${digest}`);
      expect(plain.stdout).toContain('Signer         none (anonymous stamp)');
      expect(matching.code).toBe(0);
      expect(JSON.parse(matching.stdout)).toMatchObject({ expectedHashMatches: true, status: 'OK' });
      expect(mismatch.code).toBe(1);
      expect(mismatch.stdout).toContain('FAIL: Hash mismatch');
      expect(mismatch.stdout).toContain('Expected hash  differs');
      expect(wrongNetwork.code).toBe(1);
      expect(wrongNetwork.stdout).toContain('select the matching network or trust base');
      expect(fromStdin.code).toBe(0);
      expect(inspected.code).toBe(0);
      expect(inspected.stdout).toContain('UNVERIFIED');
    },
    TIMEOUT,
  );

  it(
    'puts the JSON object on stdout even when the token would go there',
    async () => {
      const result = await runCli(['stamp', otherDigest, '--out', '-', '--json'], { cwd, env });
      expect(result.code).toBe(0);
      const parsed = JSON.parse(result.stdout) as Record<string, unknown>;
      expect(parsed).toMatchObject({ command: 'stamp', out: null });
      expect(parsed.token).toMatch(/^[0-9a-f]+$/);
      expect(parsed).toMatchObject({ hash: { algorithm: 'SHA-256', digest: otherDigest } });
    },
    TIMEOUT,
  );

  it(
    'stamps with a generated key and reports the signer',
    async () => {
      const keyFile = path.join(cwd, 'signer.key');
      const keygen = await runCli(['keygen', '--out', keyFile, '--json'], { cwd });
      expect(keygen.code).toBe(0);
      const { publicKey } = JSON.parse(keygen.stdout) as { publicKey: string };

      const result = await runCli(['stamp', digest, '--key-file', keyFile, '--sign', '--out', signedToken], {
        cwd,
        env,
      });
      expect(result.code).toBe(0);
      expect(result.stdout).toContain(`Signer         ${publicKey}`);

      const verified = await runCli(['verify', signedToken, '--hash', digest, '--json'], { cwd });
      expect(verified.code).toBe(0);
      expect(JSON.parse(verified.stdout)).toMatchObject({ expectedHashMatches: true, signer: publicKey, status: 'OK' });
    },
    TIMEOUT,
  );

  itWritesFixtures(
    'refreshes the committed fixtures',
    async () => {
      const fixtures = path.resolve('tests/fixtures');
      await mkdir(fixtures, { recursive: true });
      await copyFile(anonymousToken, path.join(fixtures, `${TEST_NETWORK}-anonymous.cbor`));
      await copyFile(signedToken, path.join(fixtures, `${TEST_NETWORK}-signed.cbor`));
    },
    TIMEOUT,
  );
});
