import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';

import { SigningService } from '@unicitylabs/state-transition-sdk/lib/crypto/secp256k1/SigningService.js';
import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';

import { usageError } from './errors.js';
import {
  bundledTrustBase,
  INetworkSelection,
  isNetworkName,
  ITimestampNetwork,
  ITrustBaseChoice,
  loadTrustBase,
  NETWORK_NAMES,
  NetworkName,
  resolveNetwork,
} from './lib/networks.js';
import { DEFAULT_TIMEOUT_MS } from './lib/TimestampClient.js';

/** 32 bytes as hex, any case, optional 0x prefix. Shared by digests and private keys. */
const HEX_32_BYTES = /^(0x)?[0-9a-fA-F]{64}$/;
/** Hex characters of the digest used in the default output file name; 64 bits is plenty for one directory. */
const OUTPUT_NAME_DIGEST_CHARS = 16;
/** Read size for hashing files; large chunks cut the streaming overhead on big inputs. */
const HASH_CHUNK_BYTES = 4 << 20;

export interface INetworkFlags {
  readonly gateway?: string;
  readonly network?: string;
  readonly trustBase?: string;
}

export interface IStampFlags extends INetworkFlags {
  readonly allowInsecure?: boolean;
  readonly anonymous?: boolean;
  readonly apiKey?: string;
  readonly file?: string;
  readonly force?: boolean;
  readonly keyFile?: string;
  readonly out?: string;
  readonly sign?: boolean;
  readonly timeout?: string;
}

export interface IStampConfig {
  readonly allowInsecure: boolean;
  readonly apiKey: string;
  readonly digest: Uint8Array;
  readonly force: boolean;
  readonly network: ITimestampNetwork;
  readonly out: string;
  readonly signer?: SigningService;
  readonly timeoutMs: number;
}

export interface IEnvironmentLoad {
  /**
   * Trust base path that an implicitly discovered `./.env` asked for, and which
   * was refused. Present only when something was actually dropped.
   */
  readonly refusedTrustBasePath?: string;
}

/**
 * Load `.env` with Node's built-in loader. Variables already in the environment win; Node guarantees that.
 *
 * `UNICITY_TRUST_BASE` is the exception: it names the root of trust, which decides
 * what every verification means, so it is not accepted from a file that was merely
 * found in the working directory. A token shipped next to a `.env` would otherwise
 * verify against whatever trust base the sender chose. `--trust-base` and an
 * explicit `--dotenv` are deliberate acts and still work.
 *
 * @param {string} [envFile] Explicit file; when given it must exist.
 * @returns {IEnvironmentLoad} What was refused, if anything.
 * @throws {CliError} If an explicit env file is missing.
 */
export function loadEnvironment(envFile?: string): IEnvironmentLoad {
  const inheritedTrustBasePath = process.env.UNICITY_TRUST_BASE;
  try {
    process.loadEnvFile(envFile);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
      throw error;
    }
    if (envFile !== undefined) {
      throw usageError(`Env file not found: ${envFile}`, { cause: error });
    }
  }

  const loadedTrustBasePath = process.env.UNICITY_TRUST_BASE;
  if (envFile === undefined && inheritedTrustBasePath === undefined && loadedTrustBasePath !== undefined) {
    delete process.env.UNICITY_TRUST_BASE;
    return { refusedTrustBasePath: loadedTrustBasePath };
  }
  return {};
}

function parseHex32(input: string, message: string): Uint8Array {
  const trimmed = input.trim();
  if (!HEX_32_BYTES.test(trimmed)) {
    throw usageError(message);
  }
  return HexConverter.decode(trimmed);
}

/**
 * @param {string} input 64 hex characters, any case, optional 0x prefix.
 * @returns {Uint8Array} 32-byte digest.
 * @throws {CliError} If the input is not a SHA-256 digest.
 */
export function parseDigest(input: string): Uint8Array {
  return parseHex32(input, `Expected a SHA-256 digest of 64 hex characters, got '${input}'.`);
}

/**
 * @param {string} input 64 hex characters, any case, optional 0x prefix, surrounding whitespace allowed.
 * @returns {Uint8Array} 32-byte secp256k1 private key.
 * @throws {CliError} If the input is not a key.
 */
export function parsePrivateKey(input: string): Uint8Array {
  return parseHex32(input, 'Private key must be 64 hex characters.');
}

/**
 * @param {string} value Candidate network name.
 * @returns {NetworkName} The name, narrowed.
 * @throws {CliError} If it is not a bundled network.
 */
export function parseNetworkName(value: string): NetworkName {
  if (!isNetworkName(value)) {
    throw usageError(`Unknown network '${value}'; expected one of ${NETWORK_NAMES.join(', ')}.`);
  }
  return value;
}

/**
 * SHA-256 of a file, streamed. The file never leaves the machine.
 *
 * @param {string} path File to hash.
 * @returns {Promise<Uint8Array>} 32-byte digest.
 */
export async function hashFile(path: string): Promise<Uint8Array> {
  const hash = createHash('sha256');
  await pipeline(createReadStream(path, { highWaterMark: HASH_CHUNK_BYTES }), hash);
  return new Uint8Array(hash.digest());
}

/**
 * Reject two sources for one digest.
 *
 * Separate from {@link resolveDigest} so a command can refuse the contradiction
 * before it reads anything: `verify` returns early on a token whose network it
 * cannot place, and a contradiction on the command line is a usage error either
 * way.
 *
 * @param {string} [digest] Digest given directly.
 * @param {string} [file] File to hash instead.
 * @param {string} digestFlag How the digest option is named in the error.
 * @throws {CliError} If both are given.
 */
export function assertOneDigestSource(digest?: string, file?: string, digestFlag = 'a digest'): void {
  if (digest !== undefined && file !== undefined) {
    throw usageError(`Pass either ${digestFlag} or --file, not both.`);
  }
}

/**
 * Resolve a digest from at most one of a digest string and a file to hash.
 *
 * @param {string} [digest] Digest as hex.
 * @param {string} [file] File to hash instead.
 * @param {string} digestFlag How the digest option is named in the error for passing both.
 * @returns {Promise<Uint8Array|undefined>} 32-byte digest, or undefined when neither was given.
 * @throws {CliError} If both are given or the digest is malformed.
 */
export async function resolveDigest(
  digest?: string,
  file?: string,
  digestFlag = 'a digest',
): Promise<Uint8Array | undefined> {
  assertOneDigestSource(digest, file, digestFlag);
  if (digest !== undefined) {
    return parseDigest(digest);
  }
  return file === undefined ? undefined : await hashFile(file);
}

/**
 * Network selection for stamping: flags, then environment, then the mainnet default.
 *
 * @param {INetworkFlags} flags Command-line flags.
 * @param {NodeJS.ProcessEnv} env Environment.
 * @returns {INetworkSelection} Validated selection.
 * @throws {CliError} On an unknown network name or an invalid gateway URL.
 */
export function resolveNetworkSelection(flags: INetworkFlags, env: NodeJS.ProcessEnv = process.env): INetworkSelection {
  const gatewayUrl = flags.gateway ?? env.UNICITY_GATEWAY_URL;
  if (gatewayUrl !== undefined) {
    try {
      new URL(gatewayUrl);
    } catch (error) {
      throw usageError(`Invalid gateway URL '${gatewayUrl}'.`, { cause: error });
    }
  }
  return {
    gatewayUrl,
    network: parseNetworkName(flags.network ?? env.UNICITY_NETWORK ?? 'mainnet'),
    trustBasePath: flags.trustBase ?? env.UNICITY_TRUST_BASE,
  };
}

/**
 * Trust base explicitly chosen for verification: a file, or a named network.
 * `UNICITY_NETWORK` is not consulted; it configures stamping, and a token says
 * which network it belongs to.
 *
 * The provenance travels with the trust base so the verdict can say which root of
 * trust produced it. An override that looked like the bundled pin would make a
 * forged token indistinguishable from a genuine one.
 *
 * @param {INetworkFlags} flags Command-line flags.
 * @param {NodeJS.ProcessEnv} env Environment.
 * @returns {Promise<ITrustBaseChoice|undefined>} The override, or undefined to derive it from the token.
 * @throws {CliError} On an unknown network name.
 */
export async function resolveTrustBaseOverride(
  flags: INetworkFlags,
  env: NodeJS.ProcessEnv = process.env,
): Promise<ITrustBaseChoice | undefined> {
  const trustBasePath = flags.trustBase ?? env.UNICITY_TRUST_BASE;
  if (trustBasePath !== undefined) {
    return {
      source: { kind: 'file', path: path.resolve(trustBasePath) },
      trustBase: await loadTrustBase(trustBasePath),
    };
  }
  if (flags.network === undefined) {
    return undefined;
  }
  const network = parseNetworkName(flags.network);
  return { source: { kind: 'bundled', network }, trustBase: bundledTrustBase(network) };
}

/**
 * Node timers hold the delay in a *signed* 32-bit integer, so 2147483647 ms is the
 * longest wait that can be represented. A larger delay is not refused: it is
 * silently reduced to 1 ms, with only a `TimeoutOverflowWarning` to show for it.
 *
 * That matters here because the signal is constructed after the certification
 * request has been submitted and billed. A value just over the limit would
 * therefore certify the digest and then abandon the proof wait immediately —
 * losing the paid stamp, which is the very thing this bound exists to prevent.
 * Enforcing it at parse time keeps the failure before the network call.
 */
const MAX_TIMEOUT_SECONDS = 2_147_483;

/**
 * @param {string} [value] Flag or environment value.
 * @returns {number} Timeout in milliseconds.
 * @throws {CliError} If the value is not a positive integer, or is too large to wait for.
 */
export function parseTimeoutSeconds(value?: string): number {
  if (value === undefined) {
    return DEFAULT_TIMEOUT_MS;
  }
  const seconds = Number(value);
  if (!Number.isInteger(seconds) || seconds <= 0) {
    throw usageError(`--timeout must be a positive integer number of seconds, got '${value}'.`);
  }
  if (seconds > MAX_TIMEOUT_SECONDS) {
    throw usageError(`--timeout must be at most ${MAX_TIMEOUT_SECONDS} seconds, got '${value}'.`);
  }
  return seconds * 1000;
}

async function readKeyFile(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch (error) {
    throw usageError(`Cannot read key file ${file}.`, { cause: error });
  }
}

async function resolveSigner(flags: IStampFlags, env: NodeJS.ProcessEnv): Promise<SigningService | undefined> {
  if (flags.anonymous && flags.sign) {
    throw usageError('--anonymous and --sign contradict each other.');
  }
  if (flags.anonymous) {
    return undefined;
  }
  if (flags.keyFile !== undefined) {
    return new SigningService(parsePrivateKey(await readKeyFile(flags.keyFile)));
  }
  const keyHex = env.UNICITY_PRIVATE_KEY;
  if (keyHex === undefined || keyHex.trim() === '') {
    if (flags.sign) {
      throw usageError('--sign requires a key: pass --key-file or set UNICITY_PRIVATE_KEY.');
    }
    return undefined;
  }
  return new SigningService(parsePrivateKey(keyHex));
}

/**
 * Fail before any network contact when the token cannot be written afterwards.
 *
 * The write happens once the stamp has been certified and billed, so the point of
 * these checks is to catch the reachable mistakes while they are still free. A
 * mistyped or read-only `--out` directory is the realistic one; an existing output
 * file is the other. Both are checked here, the directory even under `--force`,
 * which still needs somewhere to write.
 *
 * This cannot be airtight — the directory may stop being writable between here and
 * the write, and nothing catches a full disk — which is why `writeCertifiedToken`
 * still prints the token on failure. Prevention for what is foreseeable, recovery
 * for what is not.
 *
 * @param {string} out Output path, or `-` for stdout.
 * @param {boolean} force Whether an existing file may be replaced.
 * @throws {CliError} If the directory cannot be written to, or the file exists without `--force`.
 */
async function assertWritable(out: string, force: boolean): Promise<void> {
  if (out === '-') {
    return;
  }

  const exists = await access(out).then(
    () => true,
    () => false,
  );
  if (exists) {
    if (!force) {
      throw usageError(`Refusing to overwrite ${out}; pass --force or another --out.`);
    }
    // Replacing an existing file truncates it in place, which needs write
    // permission on the file and nothing from the directory — so a read-only
    // directory is no obstacle here, and must not be treated as one.
    try {
      await access(out, constants.W_OK);
    } catch (error) {
      throw usageError(`Cannot write to ${out}.`, { cause: error });
    }
    return;
  }

  // Creating a new entry is the case that needs the directory itself. Symlinks are
  // not resolved here, so a dangling link in a read-only directory pointing into a
  // writable one is refused even though the write would have worked. That is
  // accepted deliberately: the check errs towards refusing before anything is
  // billed, which costs a retry, where erring the other way costs a stamp.
  const directory = path.dirname(path.resolve(out));
  try {
    await access(directory, constants.W_OK | constants.X_OK);
  } catch (error) {
    throw usageError(`Cannot write to the output directory ${directory}.`, { cause: error });
  }
}

/**
 * Everything `stamp` needs, validated before any network contact. Cheap checks
 * run first so a misconfiguration is reported before a large file is hashed.
 *
 * @param {string} [digestArgument] Positional digest.
 * @param {IStampFlags} flags Command-line flags.
 * @param {NodeJS.ProcessEnv} env Environment, after `.env` was loaded.
 * @returns {Promise<IStampConfig>} Resolved configuration.
 * @throws {CliError} On any missing or invalid setting.
 */
export async function resolveStampConfig(
  digestArgument: string | undefined,
  flags: IStampFlags,
  env: NodeJS.ProcessEnv = process.env,
): Promise<IStampConfig> {
  if (digestArgument === undefined && flags.file === undefined) {
    throw usageError('Pass a SHA-256 digest or --file <path>.');
  }

  const apiKey = (flags.apiKey ?? env.UNICITY_API_KEY)?.trim();
  if (!apiKey) {
    throw usageError('No API key. Set UNICITY_API_KEY in the environment or .env, or pass --api-key.');
  }

  const network = await resolveNetwork(resolveNetworkSelection(flags, env));
  const allowInsecure = flags.allowInsecure ?? false;
  if (new URL(network.gatewayUrl).protocol !== 'https:' && !allowInsecure) {
    throw usageError(
      'The API key must not be sent over plain HTTP. Use an https gateway, or pass --allow-insecure for a local aggregator.',
    );
  }

  const signer = await resolveSigner(flags, env);
  const timeoutMs = parseTimeoutSeconds(flags.timeout ?? env.UNICITY_TIMEOUT);
  const force = flags.force ?? false;
  if (flags.out !== undefined) {
    await assertWritable(flags.out, force);
  }

  const digest = (await resolveDigest(digestArgument, flags.file)) as Uint8Array;
  const out = flags.out ?? `token_${HexConverter.encode(digest).slice(0, OUTPUT_NAME_DIGEST_CHARS)}.cbor`;
  if (flags.out === undefined) {
    await assertWritable(out, force);
  }

  return { allowInsecure, apiKey, digest, force, network, out, signer, timeoutMs };
}
