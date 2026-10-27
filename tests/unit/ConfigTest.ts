import { chmod, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import {
  hashFile,
  loadEnvironment,
  loadTrustBase,
  parseDigest,
  parseNetworkName,
  parsePrivateKey,
  parseTimeoutSeconds,
  resolveDigest,
  resolveNetworkSelection,
  resolveStampConfig,
  resolveTrustBaseOverride,
} from '../../src/config.js';
import { CliError } from '../../src/errors.js';
import { NETWORKS } from '../../src/lib/networks.js';
import { DEFAULT_TIMEOUT_MS } from '../../src/lib/TimestampClient.js';
import { tempDir, TEST_DIGEST_HEX, TEST_PRIVATE_KEY_HEX, TEST_PUBLIC_KEY_HEX } from '../support/fixtures.js';

describe('parseDigest', () => {
  it('accepts upper and lower case with or without 0x', () => {
    expect(HexConverter.encode(parseDigest(TEST_DIGEST_HEX))).toEqual(TEST_DIGEST_HEX);
    expect(HexConverter.encode(parseDigest(`0x${TEST_DIGEST_HEX.toUpperCase()}`))).toEqual(TEST_DIGEST_HEX);
    expect(HexConverter.encode(parseDigest(`  ${TEST_DIGEST_HEX}\n`))).toEqual(TEST_DIGEST_HEX);
  });

  it.each(['', 'abc', TEST_DIGEST_HEX.slice(0, 63), `${TEST_DIGEST_HEX}0`, 'zz'.repeat(32)])('rejects %p', (input) => {
    expect(() => parseDigest(input)).toThrow(CliError);
    expect(() => parseDigest(input)).toThrow(/64 hex characters/);
  });
});

describe('parsePrivateKey', () => {
  it('accepts 64 hex characters with surrounding whitespace', () => {
    expect(HexConverter.encode(parsePrivateKey(`${TEST_PRIVATE_KEY_HEX}\n`))).toEqual(TEST_PRIVATE_KEY_HEX);
    expect(HexConverter.encode(parsePrivateKey(`0x${TEST_PRIVATE_KEY_HEX}`))).toEqual(TEST_PRIVATE_KEY_HEX);
  });

  it('rejects anything else', () => {
    expect(() => parsePrivateKey('01'.repeat(31))).toThrow('Private key must be 64 hex characters.');
  });
});

describe('parseNetworkName', () => {
  it('narrows known names and rejects the rest', () => {
    expect(parseNetworkName('mainnet')).toEqual('mainnet');
    expect(parseNetworkName('testnet2')).toEqual('testnet2');
    expect(() => parseNetworkName('testnet')).toThrow("Unknown network 'testnet'; expected one of mainnet, testnet2.");
  });
});

describe('parseTimeoutSeconds', () => {
  it('defaults to the client default and converts to milliseconds', () => {
    expect(parseTimeoutSeconds(undefined)).toBe(DEFAULT_TIMEOUT_MS);
    expect(parseTimeoutSeconds('5')).toBe(5000);
  });

  it.each(['0', '-1', '1.5', 'abc', ''])('rejects %p', (input) => {
    expect(() => parseTimeoutSeconds(input)).toThrow(/positive integer/);
  });

  // AbortSignal.timeout is constructed after the certification request has been
  // submitted and billed, so a delay Node cannot represent would certify the
  // digest and then abandon the wait. These have to fail before the network call.
  it.each(['2147484', '4294967', '99999999', '1000000000'])('rejects %p as too large to wait for', (input) => {
    expect(() => parseTimeoutSeconds(input)).toThrow(/at most 2147483 seconds/);
  });

  it('keeps the largest accepted delay inside the range a Node timer can hold', () => {
    // Beyond this a timer is silently reduced to 1ms rather than refused, so the
    // bound has to be asserted numerically; nothing throws to catch it.
    const NODE_TIMEOUT_MAX_MS = 2 ** 31 - 1;
    expect(parseTimeoutSeconds('2147483')).toBe(2_147_483_000);
    expect(parseTimeoutSeconds('2147483')).toBeLessThanOrEqual(NODE_TIMEOUT_MAX_MS);
    expect(parseTimeoutSeconds(undefined)).toBeLessThanOrEqual(NODE_TIMEOUT_MAX_MS);
  });
});

describe('hashFile and resolveDigest', () => {
  it('hashes a file with SHA-256 and takes at most one source', async () => {
    const file = path.join(await tempDir(), 'hello.txt');
    await writeFile(file, 'hello');
    expect(HexConverter.encode(await hashFile(file))).toEqual(TEST_DIGEST_HEX);
    expect(HexConverter.encode((await resolveDigest(undefined, file))!)).toEqual(TEST_DIGEST_HEX);
    expect(HexConverter.encode((await resolveDigest(TEST_DIGEST_HEX))!)).toEqual(TEST_DIGEST_HEX);
    await expect(resolveDigest()).resolves.toBeUndefined();
    await expect(resolveDigest(TEST_DIGEST_HEX, file)).rejects.toThrow('Pass either a digest or --file, not both.');
    await expect(resolveDigest(TEST_DIGEST_HEX, file, '--hash')).rejects.toThrow(
      'Pass either --hash or --file, not both.',
    );
  });
});

describe('resolveNetworkSelection', () => {
  it('prefers flags, then the environment, then mainnet', () => {
    expect(resolveNetworkSelection({}, {})).toEqual({
      gatewayUrl: undefined,
      network: 'mainnet',
      trustBasePath: undefined,
    });
    expect(resolveNetworkSelection({}, { UNICITY_NETWORK: 'testnet2' }).network).toEqual('testnet2');
    expect(resolveNetworkSelection({ network: 'mainnet' }, { UNICITY_NETWORK: 'testnet2' }).network).toEqual('mainnet');
    expect(
      resolveNetworkSelection({ gateway: 'https://g.example' }, { UNICITY_GATEWAY_URL: 'https://env.example' })
        .gatewayUrl,
    ).toEqual('https://g.example');
    expect(resolveNetworkSelection({}, { UNICITY_TRUST_BASE: '/tb.json' }).trustBasePath).toEqual('/tb.json');
  });

  it('rejects unknown networks and invalid URLs', () => {
    expect(() => resolveNetworkSelection({ network: 'testnet' }, {})).toThrow(/Unknown network 'testnet'/);
    expect(() => resolveNetworkSelection({ gateway: 'not a url' }, {})).toThrow(/Invalid gateway URL/);
  });
});

describe('loadTrustBase', () => {
  it('parses a trust base file', async () => {
    const file = path.join(await tempDir(), 'trust-base.json');
    await writeFile(file, JSON.stringify(NETWORKS.testnet2.trustBaseJson));
    expect((await loadTrustBase(file)).networkId.id).toBe(4);
  });

  it('surfaces unreadable and malformed files', async () => {
    await expect(loadTrustBase('/nonexistent/trust-base.json')).rejects.toMatchObject({ code: 'ENOENT' });
    const file = path.join(await tempDir(), 'broken.json');
    await writeFile(file, '{"version": "1"}');
    await expect(loadTrustBase(file)).rejects.toThrow();
  });
});

describe('resolveTrustBaseOverride', () => {
  it('returns nothing without flags, so the token decides', async () => {
    await expect(resolveTrustBaseOverride({}, {})).resolves.toBeUndefined();
    await expect(resolveTrustBaseOverride({}, { UNICITY_NETWORK: 'testnet2' })).resolves.toBeUndefined();
  });

  it('honours --network, --trust-base and UNICITY_TRUST_BASE', async () => {
    expect((await resolveTrustBaseOverride({ network: 'testnet2' }, {}))?.trustBase.networkId.id).toBe(4);
    const file = path.join(await tempDir(), 'tb.json');
    await writeFile(file, JSON.stringify(NETWORKS.testnet2.trustBaseJson));
    expect((await resolveTrustBaseOverride({ trustBase: file }, {}))?.trustBase.networkId.id).toBe(4);
    expect((await resolveTrustBaseOverride({}, { UNICITY_TRUST_BASE: file }))?.trustBase.networkId.id).toBe(4);
    await expect(resolveTrustBaseOverride({ network: 'devnet' }, {})).rejects.toThrow(/Unknown network 'devnet'/);
  });

  it('reports where the trust base came from, so a verdict can disclose it', async () => {
    expect((await resolveTrustBaseOverride({ network: 'testnet2' }, {}))?.source).toEqual({
      kind: 'bundled',
      network: 'testnet2',
    });
    const file = path.join(await tempDir(), 'tb.json');
    await writeFile(file, JSON.stringify(NETWORKS.testnet2.trustBaseJson));
    expect((await resolveTrustBaseOverride({ trustBase: file }, {}))?.source).toEqual({
      kind: 'file',
      path: path.resolve(file),
    });
  });
});

describe('loadEnvironment', () => {
  it('fails on an explicit file that does not exist', () => {
    expect(() => loadEnvironment('/nonexistent/.env')).toThrow('Env file not found: /nonexistent/.env');
  });

  it('loads an explicit file and ignores a missing default file', async () => {
    const directory = await tempDir();
    const file = path.join(directory, 'test.env');
    await writeFile(file, 'UNICITY_CONFIG_TEST_LOADED=yes\n');
    expect(() => loadEnvironment(file)).not.toThrow();
    const previous = process.cwd();
    process.chdir(directory);
    try {
      expect(() => loadEnvironment()).not.toThrow();
    } finally {
      process.chdir(previous);
    }
  });

  // `UNICITY_TRUST_BASE` is deliberately not accepted from an implicitly loaded
  // `./.env`; see the refusal in loadEnvironment. It cannot be covered here:
  // `process.loadEnvFile` is native and writes to the real `process.env`, while
  // Jest hands each test file a copy, so nothing a `.env` sets is ever visible in
  // process. That is also why the test above only asserts it does not throw. The
  // behaviour is covered end to end in tests/e2e/CliOfflineTest.ts, which runs the
  // built CLI as a child process.

  it('leaves an inherited UNICITY_TRUST_BASE alone', () => {
    process.env.UNICITY_TRUST_BASE = '/inherited.json';
    try {
      expect(loadEnvironment().refusedTrustBasePath).toBeUndefined();
      expect(process.env.UNICITY_TRUST_BASE).toEqual('/inherited.json');
    } finally {
      delete process.env.UNICITY_TRUST_BASE;
    }
  });
});

describe('resolveStampConfig', () => {
  const env = { UNICITY_API_KEY: 'sk_test' };

  it('resolves defaults: mainnet, anonymous, 60 s, token_<16 hex>.cbor', async () => {
    const config = await resolveStampConfig(TEST_DIGEST_HEX, {}, env);
    expect(config.network.preset).toEqual('mainnet');
    expect(config.network.gatewayUrl).toEqual('https://gateway.mainnet.unicity.network');
    expect(config.network.trustBase.networkId.id).toBe(1);
    expect(config.signer).toBeUndefined();
    expect(config.timeoutMs).toBe(DEFAULT_TIMEOUT_MS);
    expect(config.out).toEqual(`token_${TEST_DIGEST_HEX.slice(0, 16)}.cbor`);
    expect(config.apiKey).toEqual('sk_test');
    expect(config.allowInsecure).toBe(false);
  });

  // The token is written only after the stamp has been certified and billed, so a
  // destination that cannot be written has to be rejected here, while it is free.
  // The permissions required differ by case: replacing a file truncates it in
  // place and needs nothing from the directory, whereas creating one does.
  describe('output destination checks', () => {
    let directory: string;

    beforeEach(async () => {
      directory = await tempDir('proof-cli-out-');
    });

    afterEach(async () => {
      await chmod(directory, 0o700).catch(() => undefined);
    });

    it('rejects a directory that does not exist', async () => {
      const out = path.join(directory, 'missing', 'token.cbor');
      await expect(resolveStampConfig(TEST_DIGEST_HEX, { out }, env)).rejects.toThrow(/Cannot write to the output/);
    });

    it('rejects creating a file in a read-only directory', async () => {
      await chmod(directory, 0o500);
      const out = path.join(directory, 'token.cbor');
      await expect(resolveStampConfig(TEST_DIGEST_HEX, { force: true, out }, env)).rejects.toThrow(
        /Cannot write to the output/,
      );
    });

    it('allows replacing a writable file even in a read-only directory', async () => {
      const out = path.join(directory, 'token.cbor');
      await writeFile(out, 'existing', { mode: 0o600 });
      await chmod(directory, 0o500);
      const config = await resolveStampConfig(TEST_DIGEST_HEX, { force: true, out }, env);
      expect(config.out).toEqual(out);
    });

    it('rejects replacing a file it cannot write to', async () => {
      const out = path.join(directory, 'token.cbor');
      await writeFile(out, 'existing', { mode: 0o400 });
      await expect(resolveStampConfig(TEST_DIGEST_HEX, { force: true, out }, env)).rejects.toThrow(
        /Cannot write to .*token\.cbor/,
      );
    });

    it('still refuses an existing file without --force', async () => {
      const out = path.join(directory, 'token.cbor');
      await writeFile(out, 'existing', { mode: 0o600 });
      await expect(resolveStampConfig(TEST_DIGEST_HEX, { out }, env)).rejects.toThrow(/Refusing to overwrite/);
    });
  });

  it('requires a digest or a file, and an API key', async () => {
    await expect(resolveStampConfig(undefined, {}, env)).rejects.toThrow('Pass a SHA-256 digest or --file <path>.');
    await expect(resolveStampConfig(TEST_DIGEST_HEX, {}, {})).rejects.toThrow(/No API key/);
    await expect(resolveStampConfig(TEST_DIGEST_HEX, {}, { UNICITY_API_KEY: '  ' })).rejects.toThrow(/No API key/);
  });

  it('reports cheap configuration errors before hashing the file', async () => {
    await expect(resolveStampConfig(undefined, { file: '/nonexistent/big.bin' }, {})).rejects.toThrow(/No API key/);
  });

  it('lets flags beat the environment', async () => {
    const config = await resolveStampConfig(
      TEST_DIGEST_HEX,
      { apiKey: 'sk_flag', network: 'testnet2', timeout: '5' },
      { ...env, UNICITY_NETWORK: 'mainnet', UNICITY_TIMEOUT: '9' },
    );
    expect(config.apiKey).toEqual('sk_flag');
    expect(config.network.preset).toEqual('testnet2');
    expect(config.timeoutMs).toBe(5000);
  });

  it('signs when a key is configured through the environment or a file', async () => {
    const fromEnv = await resolveStampConfig(
      TEST_DIGEST_HEX,
      {},
      { ...env, UNICITY_PRIVATE_KEY: TEST_PRIVATE_KEY_HEX },
    );
    expect(HexConverter.encode(fromEnv.signer!.publicKey)).toEqual(TEST_PUBLIC_KEY_HEX);

    const keyFile = path.join(await tempDir(), 'k.key');
    await writeFile(keyFile, `${TEST_PRIVATE_KEY_HEX}\n`);
    const fromFile = await resolveStampConfig(TEST_DIGEST_HEX, { keyFile }, env);
    expect(fromFile.signer).toBeDefined();
  });

  it('--anonymous ignores a configured key and --sign insists on one', async () => {
    const anonymous = await resolveStampConfig(
      TEST_DIGEST_HEX,
      { anonymous: true },
      { ...env, UNICITY_PRIVATE_KEY: TEST_PRIVATE_KEY_HEX },
    );
    expect(anonymous.signer).toBeUndefined();
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { sign: true }, env)).rejects.toThrow(/--sign requires a key/);
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { anonymous: true, sign: true }, env)).rejects.toThrow(
      '--anonymous and --sign contradict each other.',
    );
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { keyFile: '/nonexistent.key' }, env)).rejects.toThrow(
      /Cannot read key file/,
    );
    const emptyKeyFile = path.join(await tempDir(), 'empty.key');
    await writeFile(emptyKeyFile, '');
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { keyFile: emptyKeyFile }, env)).rejects.toThrow(
      /Private key must be 64 hex characters/,
    );
  });

  it('refuses plain HTTP for the API key unless --allow-insecure', async () => {
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { gateway: 'http://localhost:3000' }, env)).rejects.toThrow(
      /plain HTTP/,
    );
    const allowed = await resolveStampConfig(
      TEST_DIGEST_HEX,
      { allowInsecure: true, gateway: 'http://localhost:3000' },
      env,
    );
    expect(allowed.allowInsecure).toBe(true);
    expect(allowed.network.gatewayUrl).toEqual('http://localhost:3000');
  });

  it('refuses to overwrite an existing output file unless --force', async () => {
    const out = path.join(await tempDir(), 'existing.cbor');
    await writeFile(out, 'x');
    await expect(resolveStampConfig(TEST_DIGEST_HEX, { out }, env)).rejects.toThrow(/Refusing to overwrite/);
    const forced = await resolveStampConfig(TEST_DIGEST_HEX, { force: true, out }, env);
    expect(forced.force).toBe(true);
    const toStdout = await resolveStampConfig(TEST_DIGEST_HEX, { out: '-' }, env);
    expect(toStdout.out).toEqual('-');
  });
});
