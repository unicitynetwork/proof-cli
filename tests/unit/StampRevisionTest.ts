import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { StateTransitionClient } from '@unicitylabs/state-transition-sdk/lib/StateTransitionClient.js';
import { Token } from '@unicitylabs/state-transition-sdk/lib/transaction/Token.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { stampRevisionWith, writeRevisionToken } from '../../src/commands/stampRevision.js';
import { IStampRevisionConfig, parsePublicKey, resolveStampRevisionConfig } from '../../src/config.js';
import { EXIT_USAGE, EXIT_VERIFICATION_FAILED, toExitCode } from '../../src/errors.js';
import { verifyLineage } from '../../src/lib/lineage/LineageVerification.js';
import { testContext } from '../support/context.js';
import {
  OTHER_DIGEST,
  OTHER_DIGEST_HEX,
  tempDir,
  TEST_DIGEST,
  TEST_DIGEST_HEX,
  TEST_PRIVATE_KEY,
  TEST_PRIVATE_KEY_HEX,
  TEST_PUBLIC_KEY_HEX,
} from '../support/fixtures.js';
import { TestAggregatorClient } from '../support/TestAggregatorClient.js';

const ENV = { UNICITY_API_KEY: 'key' };

describe('resolveStampRevisionConfig', () => {
  let directory: string;
  let keyFile: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-revision-');
    keyFile = path.join(directory, 'producer.key');
    await writeFile(keyFile, `${TEST_PRIVATE_KEY_HEX}\n`);
  });

  const base = (): Record<string, string> => ({
    keyFile,
    recipientKey: TEST_PUBLIC_KEY_HEX,
    tokenFile: path.join(directory, 'doc.lineage'),
  });

  it('resolves a new lineage', async () => {
    const config = await resolveStampRevisionConfig(TEST_DIGEST_HEX, base(), ENV);
    expect(config.tokenBytes).toBeNull();
    expect(config.digest).toEqual(TEST_DIGEST);
    expect(config.privateKey).toEqual(TEST_PRIVATE_KEY);
    expect(HexConverter.encode(config.recipientKey as Uint8Array)).toEqual(TEST_PUBLIC_KEY_HEX);
    expect(config.network.preset).toEqual('mainnet');
  });

  it('reads an existing token file and a recipient key file', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await writeFile(tokenFile, 'abcd');
    const recipientKeyFile = path.join(directory, 'next.pub');
    await writeFile(recipientKeyFile, ` ${TEST_PUBLIC_KEY_HEX.toUpperCase()}\n`);
    const config = await resolveStampRevisionConfig(TEST_DIGEST_HEX, { keyFile, recipientKeyFile, tokenFile }, ENV);
    expect(config.tokenBytes).toEqual(new TextEncoder().encode('abcd'));
    expect(HexConverter.encode(config.recipientKey as Uint8Array)).toEqual(TEST_PUBLIC_KEY_HEX);
  });

  it('resolves --finalize to no next producer', async () => {
    const config = await resolveStampRevisionConfig(
      TEST_DIGEST_HEX,
      { ...base(), finalize: true, recipientKey: undefined },
      ENV,
    );
    expect(config.recipientKey).toBeNull();
  });

  it.each([
    ['no digest source', undefined, {}, 'Pass a SHA-256 digest or --file <path>.'],
    ['both digest sources', TEST_DIGEST_HEX, { file: 'x' }, 'Pass either a digest or --file, not both.'],
    ['no token file', TEST_DIGEST_HEX, { tokenFile: undefined }, /--token-file/],
    ['no key file', TEST_DIGEST_HEX, { keyFile: undefined }, /--key-file/],
    [
      'no recipient',
      TEST_DIGEST_HEX,
      { recipientKey: undefined },
      /--recipient-key or --recipient-key-file, or pass --finalize/,
    ],
    [
      'both recipients',
      TEST_DIGEST_HEX,
      { recipientKeyFile: 'x' },
      'Pass only one of --recipient-key, --recipient-key-file and --finalize; got --recipient-key and --recipient-key-file.',
    ],
    [
      'a recipient and --finalize',
      TEST_DIGEST_HEX,
      { finalize: true },
      'Pass only one of --recipient-key, --recipient-key-file and --finalize; got --recipient-key and --finalize.',
    ],
    [
      'a recipient file and --finalize',
      TEST_DIGEST_HEX,
      { finalize: true, recipientKey: undefined, recipientKeyFile: 'x' },
      /got --recipient-key-file and --finalize/,
    ],
    [
      'all three',
      TEST_DIGEST_HEX,
      { finalize: true, recipientKeyFile: 'x' },
      /got --recipient-key and --recipient-key-file and --finalize/,
    ],
    ['a malformed recipient', TEST_DIGEST_HEX, { recipientKey: '04abcd' }, /compressed secp256k1 public key/],
    [
      'a missing recipient file',
      TEST_DIGEST_HEX,
      { recipientKey: undefined, recipientKeyFile: '/no/such' },
      /Cannot read/,
    ],
  ])('refuses %s', async (_, digest, overrides, message) => {
    await expect(resolveStampRevisionConfig(digest, { ...base(), ...overrides }, ENV)).rejects.toMatchObject({
      exitCode: EXIT_USAGE,
    });
    await expect(resolveStampRevisionConfig(digest, { ...base(), ...overrides }, ENV)).rejects.toThrow(message);
  });

  it('refuses a token file in a directory that does not exist', async () => {
    await expect(
      resolveStampRevisionConfig(TEST_DIGEST_HEX, { ...base(), tokenFile: path.join(directory, 'no', 'x') }, ENV),
    ).rejects.toThrow(/Cannot write to the token file directory/);
  });

  it('requires an API key', async () => {
    await expect(resolveStampRevisionConfig(TEST_DIGEST_HEX, base(), {})).rejects.toThrow(/No API key/);
  });
});

describe('parsePublicKey', () => {
  it('accepts a compressed key with or without 0x', () => {
    expect(HexConverter.encode(parsePublicKey(`0x${TEST_PUBLIC_KEY_HEX}`))).toEqual(TEST_PUBLIC_KEY_HEX);
  });

  it('rejects a point that is not on the curve', () => {
    expect(() => parsePublicKey(`02${'ff'.repeat(32)}`)).toThrow(/not a point/);
  });
});

describe('stampRevisionWith', () => {
  const aggregator = TestAggregatorClient.create();
  const client = new StateTransitionClient(aggregator);
  const bob = SigningService.generatePrivateKey();
  const bobPublic = new SigningService(bob).publicKey;
  let directory: string;

  beforeEach(async () => {
    directory = await tempDir('proof-cli-revision-');
  });

  function config(overrides: Partial<IStampRevisionConfig>): IStampRevisionConfig {
    return {
      allowInsecure: false,
      apiKey: 'key',
      digest: TEST_DIGEST,
      network: { gatewayUrl: 'https://gateway.test', preset: 'testnet2', trustBase: aggregator.rootTrustBase },
      privateKey: TEST_PRIVATE_KEY,
      recipientKey: bobPublic,
      timeoutMs: 2_000,
      tokenBytes: null,
      tokenFile: path.join(directory, 'doc.lineage'),
      ...overrides,
    };
  }

  it('creates the token file, then appends to it', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    const first = testContext({ json: true });
    expect(await stampRevisionWith(config({}), client, first.context)).toBe(0);
    expect(first.json()).toMatchObject({
      command: 'stamp-revision',
      created: true,
      hash: { algorithm: 'SHA-256', digest: TEST_DIGEST_HEX },
      nextProducer: HexConverter.encode(bobPublic),
      revision: '0',
      signer: TEST_PUBLIC_KEY_HEX,
      tokenFile,
    });

    const second = testContext();
    const tokenBytes = new Uint8Array(await readFile(tokenFile));
    expect(
      await stampRevisionWith(
        config({
          digest: OTHER_DIGEST,
          privateKey: bob,
          recipientKey: HexConverter.decode(TEST_PUBLIC_KEY_HEX),
          tokenBytes,
        }),
        client,
        second.context,
      ),
    ).toBe(0);
    expect(second.stdout()).toContain('Revision       1\n');
    expect(second.stdout()).toContain(`Stamped        SHA-256 ${OTHER_DIGEST_HEX}`);
    expect(await readdir(directory)).toEqual(['doc.lineage']);

    const token = await Token.fromCBOR(new Uint8Array(await readFile(tokenFile)));
    expect(token.transactions).toHaveLength(1);
    expect((await verifyLineage(token, aggregator.rootTrustBase)).status).toEqual('OK');
  });

  it('finalizes a lineage, after which nothing can be appended', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const tokenBytes = new Uint8Array(await readFile(tokenFile));

    const sealed = testContext({ json: true });
    expect(
      await stampRevisionWith(
        config({ digest: OTHER_DIGEST, privateKey: bob, recipientKey: null, tokenBytes }),
        client,
        sealed.context,
      ),
    ).toBe(0);
    expect(sealed.json()).toMatchObject({ finalized: true, nextProducer: null, revision: '1' });

    const text = testContext();
    const finalBytes = new Uint8Array(await readFile(tokenFile));
    expect(
      await stampRevisionWith(
        config({ digest: OTHER_DIGEST, privateKey: bob, recipientKey: null, tokenBytes }),
        client,
        text.context,
      ),
    ).toBe(0);
    expect(text.stdout()).toContain('Revision       1  (final)\n');
    expect(text.stdout()).toContain('Next producer  none; the lineage is finalized');

    const attempt = stampRevisionWith(
      config({ privateKey: bob, tokenBytes: finalBytes }),
      client,
      testContext().context,
    );
    await expect(attempt).rejects.toThrow(/finalized/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
  });

  it('creates a lineage that is final from the start', async () => {
    const sink = testContext({ json: true });
    expect(await stampRevisionWith(config({ recipientKey: null }), client, sink.context)).toBe(0);
    expect(sink.json()).toMatchObject({ created: true, finalized: true, nextProducer: null, revision: '0' });
  });

  it('accepts a token file holding hex text', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const hex = HexConverter.encode(new Uint8Array(await readFile(tokenFile)));
    await expect(
      stampRevisionWith(
        config({ privateKey: bob, tokenBytes: new TextEncoder().encode(`${hex}\n`) }),
        client,
        testContext().context,
      ),
    ).resolves.toBe(0);
  });

  it('refuses a key that is not the named producer, leaving the file alone', async () => {
    const tokenFile = path.join(directory, 'doc.lineage');
    await stampRevisionWith(config({}), client, testContext().context);
    const before = await readFile(tokenFile);
    const attempt = stampRevisionWith(config({ tokenBytes: new Uint8Array(before) }), client, testContext().context);
    await expect(attempt).rejects.toThrow(/does not match the producer/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_USAGE);
    expect(await readFile(tokenFile)).toEqual(before);
  });

  it('refuses a file that is not a token', async () => {
    const attempt = stampRevisionWith(
      config({ tokenBytes: new TextEncoder().encode('hello') }),
      client,
      testContext().context,
    );
    await expect(attempt).rejects.toThrow(/is not a token/);
    expect(toExitCode(await attempt.catch((error: unknown) => error))).toBe(EXIT_VERIFICATION_FAILED);
  });
});

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
