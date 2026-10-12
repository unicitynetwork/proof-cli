import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';

import { networkNameForId, TrustBaseSource } from './lib/networks.js';
import { ITimestampDescription, ITimestampVerificationResult } from './lib/TimestampClient.js';

/** Minimal sink the commands write to; process.stdout and process.stderr satisfy it. */
export interface IWriter {
  write(chunk: string | Uint8Array): unknown;
}

export interface IResultJson {
  readonly message: string;
  readonly results: IResultJson[];
  readonly rule: string;
  readonly status: string;
}

export interface INetworkJson {
  readonly id: number;
  readonly name: string;
}

export interface IDescriptionJson {
  readonly hash: { readonly algorithm: 'SHA-256'; readonly digest: string } | null;
  readonly network: INetworkJson;
  readonly payloadError: string | null;
  readonly recipientIsTimestampBurn: boolean;
  readonly referenceTime: string;
  readonly referenceTimeIso: string;
  readonly round: { readonly epoch: string; readonly number: string; readonly timestamp: string };
  readonly signer: string | null;
  readonly tokenId: string;
  readonly tokenTypeIsTimestamp: boolean;
  readonly transferCount: number;
}

export interface IStampJson extends Omit<IDescriptionJson, 'network'> {
  readonly command: 'stamp';
  readonly network: INetworkJson & { readonly gateway: string };
  readonly out: string | null;
  readonly token: string;
}

/** Which root of trust a verdict was produced against, as plain data. */
export interface ITrustBaseJson {
  readonly bundledNetwork: string | null;
  readonly path: string | null;
  readonly source: 'bundled' | 'file';
}

export interface IVerifyJson extends IDescriptionJson {
  readonly command: 'verify';
  readonly details: IResultJson | null;
  readonly expectedHashMatches: boolean | null;
  readonly reason: string | null;
  readonly status: 'FAIL' | 'OK';
  readonly trustBase: ITrustBaseJson | null;
}

export interface IInspectJson extends IDescriptionJson {
  readonly command: 'inspect';
  readonly verified: false;
}

export interface INotATokenJson {
  readonly command: string;
  readonly reason: string;
  readonly status: 'FAIL';
}

export interface IKeygenJson {
  readonly command: 'keygen';
  readonly out: string;
  readonly publicKey: string;
}

const LABEL_WIDTH = 15;

/**
 * @param {string} label Left column.
 * @param {string} value Right column.
 * @returns {string} One aligned output line.
 */
export function line(label: string, value: string): string {
  return `${label.padEnd(LABEL_WIDTH)}${value}`;
}

/**
 * @param {bigint} seconds Unix seconds.
 * @returns {string} ISO 8601 UTC without milliseconds.
 */
export function formatIso(seconds: bigint): string {
  return new Date(Number(seconds) * 1000).toISOString().replace('.000Z', 'Z');
}

/**
 * @param {number} networkId Network id from a token or trust base.
 * @returns {string} Preset name, or `unknown`.
 */
export function networkName(networkId: number): string {
  return networkNameForId(networkId) ?? 'unknown';
}

/**
 * @param {number} networkId Network id from a token or trust base.
 * @returns {string} `mainnet (1)`, or `unknown network (9)`.
 */
export function networkLabel(networkId: number): string {
  const name = networkNameForId(networkId);
  return name ? `${name} (${networkId})` : `unknown network (${networkId})`;
}

/**
 * @param {unknown} value JSON-safe value.
 * @returns {string} Pretty JSON with a trailing newline.
 */
export function toJsonLine(value: unknown): string {
  return `${JSON.stringify(value, null, 2)}\n`;
}

export function warningLine(message: string): string {
  return `warning: ${message}\n`;
}

/**
 * Last resort for a stamp that was certified but could not be written. `verify`
 * and `inspect` both read hex text, so this is a complete, usable copy.
 *
 * @param {Uint8Array} bytes Encoded token.
 * @returns {string} Message and token hex, for stderr.
 */
export function recoveryLines(bytes: Uint8Array): string {
  return [
    'error: the stamp was certified but could not be written.',
    'Save the token below; `unicity-timestamp verify` accepts hex text.',
    HexConverter.encode(bytes),
    '',
  ].join('\n');
}

/**
 * @param {TrustBaseSource|null} source Where the root of trust came from, or null if none was selected.
 * @returns {string} `bundled mainnet pin`, or the path of an override.
 */
export function trustBaseLabel(source: TrustBaseSource | null): string {
  if (source === null) {
    return 'none selected';
  }
  return source.kind === 'bundled'
    ? `bundled ${source.network} pin`
    : `${source.path}  (override, not the bundled pin)`;
}

/**
 * @param {TrustBaseSource|null} source Where the root of trust came from, or null if none was selected.
 * @returns {ITrustBaseJson|null} The same provenance as plain data.
 */
export function trustBaseJson(source: TrustBaseSource | null): ITrustBaseJson | null {
  if (source === null) {
    return null;
  }
  return source.kind === 'bundled'
    ? { bundledNetwork: source.network, path: null, source: 'bundled' }
    : { bundledNetwork: null, path: source.path, source: 'file' };
}

function hashLabel(description: ITimestampDescription): string {
  return description.payload
    ? `SHA-256 ${HexConverter.encode(description.payload.digest)}`
    : `unreadable (${description.payloadError ?? 'no payload'})`;
}

function signerLabel(description: ITimestampDescription): string {
  const signer = description.payload?.signer ?? null;
  return signer ? HexConverter.encode(signer) : 'none (anonymous stamp)';
}

function timeLines(description: ITimestampDescription): string[] {
  return [
    line('Certified at', `${formatIso(description.referenceTime)}  (reference time ${description.referenceTime})`),
    line(
      'Round',
      `${description.roundNumber}  (round timestamp ${description.roundTimestamp}, epoch ${description.epoch})`,
    ),
    line('Token id', HexConverter.encode(description.tokenId.bytes)),
  ];
}

/**
 * @param {ITimestampDescription} description Fields read off the token.
 * @param {string} gatewayUrl Gateway the stamp went through.
 * @param {string|null} out Absolute output path, or null when the token went to stdout.
 * @returns {string} Human summary of a stamp.
 */
export function stampText(description: ITimestampDescription, gatewayUrl: string, out: string | null): string {
  const lines = [
    line('Stamped', hashLabel(description)),
    line('Network', `${networkLabel(description.networkId.id)} via ${gatewayUrl}`),
    line('Signer', signerLabel(description)),
    ...timeLines(description),
  ];
  if (out !== null) {
    lines.push(line('Written', out));
  }
  return lines.join('\n');
}

/**
 * @param {ITimestampVerificationResult} result Verification outcome.
 * @param {TrustBaseSource} source Root of trust the verdict was produced against.
 * @returns {string} Human summary of a verification, with the SDK result tree on failure.
 */
export function verifyText(result: ITimestampVerificationResult, source: TrustBaseSource | null): string {
  // Named after the trust base that was actually used, never after the token's own
  // network id: a token carries whatever id its maker chose, so reading the name
  // off the token would let an override wear the bundled pin's name.
  const against = source?.kind === 'bundled' ? `the bundled ${source.network} trust base` : `${source?.path}`;
  const lines = [
    line(
      'Status',
      result.status === 'OK'
        ? `OK  (inclusion proof, consensus signatures and payload verified against ${against})`
        : `FAIL: ${result.reason ?? 'verification failed'}`,
    ),
    line('Network', networkLabel(result.networkId.id)),
    line('Trust base', trustBaseLabel(source)),
    line('Hash', hashLabel(result)),
  ];
  if (result.expectedDigestMatches === null) {
    lines.push(line('Expected hash', 'not checked; pass --file or --hash to confirm the token is for your document'));
  } else {
    lines.push(line('Expected hash', result.expectedDigestMatches ? 'matches' : 'differs'));
  }
  lines.push(line('Signer', signerLabel(result)), ...timeLines(result));
  if (result.status !== 'OK' && result.details !== null) {
    lines.push('', result.details.toString());
  }
  return lines.join('\n');
}

/**
 * @param {ITimestampDescription} description Fields read off the token.
 * @returns {string} Human dump of a token with no verification performed.
 */
export function inspectText(description: ITimestampDescription): string {
  return [
    line('UNVERIFIED', 'fields read from the token; nothing below has been checked'),
    line('Network', networkLabel(description.networkId.id)),
    line('Token type', description.tokenTypeIsTimestamp ? 'timestamp' : 'not a timestamp token'),
    line('Recipient', description.recipientIsTimestampBurn ? 'timestamp burn predicate' : 'other'),
    line('Transfers', String(description.transferCount)),
    line('Hash', hashLabel(description)),
    line('Signer', signerLabel(description)),
    ...timeLines(description),
  ].join('\n');
}

export function notATokenText(reason: string): string {
  return line('Status', `FAIL: ${reason}`);
}

export function notATokenJson(command: string, reason: string): INotATokenJson {
  return { command, reason, status: 'FAIL' };
}

export function keygenText(out: string, publicKey: string): string {
  return [line('Key written', `${out} (mode 0600)`), line('Public key', publicKey)].join('\n');
}

export function keygenJson(out: string, publicKey: string): IKeygenJson {
  return { command: 'keygen', out, publicKey };
}

/**
 * @param {VerificationResult<unknown>} result SDK result tree.
 * @returns {IResultJson} The same tree as plain data.
 */
export function resultTreeJson(result: VerificationResult<unknown>): IResultJson {
  return {
    message: result.message,
    results: result.results.map((child) => resultTreeJson(child)),
    rule: result.rule,
    status: String(result.status),
  };
}

/**
 * @param {ITimestampDescription} description Fields read off the token.
 * @returns {IDescriptionJson} JSON-safe fields; big integers as decimal strings.
 */
export function descriptionJson(description: ITimestampDescription): IDescriptionJson {
  const signer = description.payload?.signer ?? null;
  return {
    hash: description.payload
      ? { algorithm: 'SHA-256', digest: HexConverter.encode(description.payload.digest) }
      : null,
    network: { id: description.networkId.id, name: networkName(description.networkId.id) },
    payloadError: description.payloadError,
    recipientIsTimestampBurn: description.recipientIsTimestampBurn,
    referenceTime: description.referenceTime.toString(),
    referenceTimeIso: formatIso(description.referenceTime),
    round: {
      epoch: description.epoch.toString(),
      number: description.roundNumber.toString(),
      timestamp: description.roundTimestamp.toString(),
    },
    signer: signer ? HexConverter.encode(signer) : null,
    tokenId: HexConverter.encode(description.tokenId.bytes),
    tokenTypeIsTimestamp: description.tokenTypeIsTimestamp,
    transferCount: description.transferCount,
  };
}

export function stampJson(
  description: ITimestampDescription,
  gatewayUrl: string,
  out: string | null,
  tokenBytes: Uint8Array,
): IStampJson {
  const base = descriptionJson(description);
  return {
    command: 'stamp',
    ...base,
    network: { ...base.network, gateway: gatewayUrl },
    out,
    token: HexConverter.encode(tokenBytes),
  };
}

export function verifyJson(result: ITimestampVerificationResult, source: TrustBaseSource | null): IVerifyJson {
  return {
    command: 'verify',
    expectedHashMatches: result.expectedDigestMatches,
    reason: result.reason,
    status: result.status,
    ...descriptionJson(result),
    details: result.details ? resultTreeJson(result.details) : null,
    trustBase: trustBaseJson(source),
  };
}

export function inspectJson(description: ITimestampDescription): IInspectJson {
  return { command: 'inspect', verified: false, ...descriptionJson(description) };
}
