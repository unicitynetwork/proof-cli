import { HexConverter } from '@unicitylabs/state-transition-sdk/lib/util/HexConverter.js';
import { VerificationResult } from '@unicitylabs/state-transition-sdk/lib/verification/VerificationResult.js';

import {
  ILineageDescription,
  ILineageRevisionDescription,
  ILineageVerificationResult,
} from './lib/LineageVerification.js';
import { networkNameForId, TrustBaseSource } from './lib/networks.js';
import { ITimestampDescription, ITimestampVerificationResult } from './lib/TimestampVerification.js';

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
  readonly referenceTimeIso: string | null;
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
  /** Null when the key went to stdout, as in `stamp`. */
  readonly out: string | null;
  /** Present only when the key went to stdout; otherwise it is in the file at `out`. */
  readonly privateKey?: string;
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
 * @returns {string|null} ISO 8601 UTC without milliseconds, or null if no Date can hold it.
 */
export function toIso(seconds: bigint): string | null {
  const date = new Date(Number(seconds) * 1000);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().replace('.000Z', 'Z');
}

/**
 * @param {bigint} seconds Unix seconds.
 * @returns {string} ISO 8601 UTC without milliseconds, or a sentinel for the text output.
 */
export function formatIso(seconds: bigint): string {
  return toIso(seconds) ?? `out of range (${seconds})`;
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
    'Save the token below; `unicity-proof verify` accepts hex text.',
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

// Relies on `verify` failing closed: an OK result with no comparison can only
// mean no digest was given, never that the check was skipped.
function expectedHashLabel(result: ITimestampVerificationResult): string {
  if (result.expectedDigestMatches !== null) {
    return result.expectedDigestMatches ? 'matches' : 'differs';
  }
  return result.status === 'OK'
    ? 'not checked; pass --file or --hash to confirm the token is for your document'
    : 'not checked; verification failed';
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
    line('Expected hash', expectedHashLabel(result)),
    line('Signer', signerLabel(result)),
    ...timeLines(result),
  ];
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

export function keygenJson(out: string | null, publicKey: string, privateKey?: string): IKeygenJson {
  return { command: 'keygen', out, privateKey, publicKey };
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
    referenceTimeIso: toIso(description.referenceTime),
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

/** What `stamp-revision` reports about the revision it just certified. */
export interface IRevisionSummary {
  readonly created: boolean;
  readonly digest: Uint8Array;
  readonly epoch: bigint;
  readonly gatewayUrl: string;
  readonly networkId: number;
  /** Null when the revision finalized the lineage. */
  readonly nextProducer: Uint8Array | null;
  readonly referenceTime: bigint;
  readonly revision: bigint;
  readonly roundNumber: bigint;
  readonly roundTimestamp: bigint;
  readonly signer: Uint8Array;
  readonly tokenFile: string;
  readonly tokenId: Uint8Array;
}

export interface IRevisionJson {
  readonly command: 'stamp-revision';
  readonly created: boolean;
  /** True when this revision sealed the lineage, so that no revision can follow. */
  readonly finalized: boolean;
  readonly hash: { readonly algorithm: 'SHA-256'; readonly digest: string };
  readonly network: INetworkJson & { readonly gateway: string };
  /** Null when the revision finalized the lineage. */
  readonly nextProducer: string | null;
  readonly referenceTime: string;
  readonly referenceTimeIso: string | null;
  readonly revision: string;
  readonly round: { readonly epoch: string; readonly number: string; readonly timestamp: string };
  readonly signer: string;
  readonly tokenFile: string;
  readonly tokenId: string;
}

/**
 * @param {IRevisionSummary} summary The certified revision.
 * @returns {string} Human summary of a `stamp-revision`.
 */
export function revisionText(summary: IRevisionSummary): string {
  return [
    line(
      'Revision',
      `${summary.revision}${summary.created ? '  (new lineage)' : ''}${summary.nextProducer === null ? '  (final)' : ''}`,
    ),
    line('Stamped', `SHA-256 ${HexConverter.encode(summary.digest)}`),
    line('Network', `${networkLabel(summary.networkId)} via ${summary.gatewayUrl}`),
    line('Signed by', HexConverter.encode(summary.signer)),
    line('Next producer', keyLabel(summary.nextProducer, FINALIZED_LABEL)),
    line('Certified at', `${formatIso(summary.referenceTime)}  (reference time ${summary.referenceTime})`),
    line('Round', `${summary.roundNumber}  (round timestamp ${summary.roundTimestamp}, epoch ${summary.epoch})`),
    line('Token id', HexConverter.encode(summary.tokenId)),
    line('Written', summary.tokenFile),
  ].join('\n');
}

/**
 * @param {IRevisionSummary} summary The certified revision.
 * @returns {IRevisionJson} JSON-safe summary; big integers as decimal strings.
 */
export function revisionJson(summary: IRevisionSummary): IRevisionJson {
  return {
    command: 'stamp-revision',
    created: summary.created,
    finalized: summary.nextProducer === null,
    hash: { algorithm: 'SHA-256', digest: HexConverter.encode(summary.digest) },
    network: { gateway: summary.gatewayUrl, id: summary.networkId, name: networkName(summary.networkId) },
    nextProducer: summary.nextProducer === null ? null : HexConverter.encode(summary.nextProducer),
    referenceTime: summary.referenceTime.toString(),
    referenceTimeIso: toIso(summary.referenceTime),
    revision: summary.revision.toString(),
    round: {
      epoch: summary.epoch.toString(),
      number: summary.roundNumber.toString(),
      timestamp: summary.roundTimestamp.toString(),
    },
    signer: HexConverter.encode(summary.signer),
    tokenFile: summary.tokenFile,
    tokenId: HexConverter.encode(summary.tokenId),
  };
}

/**
 * Last resort for a revision that was certified but could not be written.
 *
 * @param {Uint8Array} bytes Encoded token, including the new revision.
 * @returns {string} Message and token hex, for stderr.
 */
export function revisionRecoveryLines(bytes: Uint8Array): string {
  return [
    'error: the revision was certified but the token file could not be written.',
    'Save the token below; `stamp-revision --token-file` accepts hex text.',
    HexConverter.encode(bytes),
    '',
  ].join('\n');
}

export interface ILineageRevisionJson {
  readonly error: string | null;
  readonly hash: { readonly algorithm: 'SHA-256'; readonly digest: string } | null;
  /** The index the revision claims, as a decimal string; null when it does not decode. */
  readonly index: string | null;
  readonly nextProducer: string | null;
  readonly referenceTime: string;
  readonly referenceTimeIso: string | null;
  readonly round: { readonly epoch: string; readonly number: string; readonly timestamp: string };
  /** Whether the revision is a seal, the final revision of the lineage. */
  readonly sealed: boolean;
  readonly signer: string | null;
}

export interface ILineageDescriptionJson {
  /** Whether the latest revision is a seal, so that no revision can follow. */
  readonly finalized: boolean;
  readonly issuer: string | null;
  readonly network: INetworkJson;
  /** Who may sign the next revision: the latest revision's next producer; null when finalized. */
  readonly nextProducer: string | null;
  readonly revisions: ILineageRevisionJson[];
  readonly tokenId: string;
  readonly tokenType: 'lineage';
}

export interface ILineageVerifyJson extends ILineageDescriptionJson {
  readonly command: 'verify';
  readonly details: IResultJson | null;
  readonly expectedHashMatches: boolean | null;
  /** Positions of the revisions carrying the expected hash; null when not checked. */
  readonly matchingRevisions: readonly number[] | null;
  readonly reason: string | null;
  readonly status: 'FAIL' | 'OK';
  readonly trustBase: ITrustBaseJson | null;
}

export interface ILineageInspectJson extends ILineageDescriptionJson {
  readonly command: 'inspect';
  readonly verified: false;
}

const FINALIZED_LABEL = 'none; the lineage is finalized (sealed and burned)';

function keyLabel(key: Uint8Array | null, otherwise: string): string {
  return key === null ? otherwise : HexConverter.encode(key);
}

function passesToLabel(revision: ILineageRevisionDescription): string {
  if (revision.burnReason !== null) {
    return revision.sealed ? 'nobody; sealed and burned' : 'burn predicate, but the revision is not a seal';
  }
  return keyLabel(revision.nextProducer, 'not a signature predicate');
}

function latestNextProducer(description: ILineageDescription): Uint8Array | null {
  return description.revisions.at(-1)?.nextProducer ?? null;
}

function lineageRevisionLines(revision: ILineageRevisionDescription, position: number): string[] {
  const claimed =
    revision.index !== null && revision.index !== BigInt(position) ? `  (claims index ${revision.index})` : '';
  return [
    line(
      `Revision ${position}`,
      revision.digest === null
        ? `unreadable (${revision.error ?? 'no revision payload'})`
        : `SHA-256 ${HexConverter.encode(revision.digest)}${claimed}${revision.sealed ? '  (final)' : ''}`,
    ),
    line('  Signed by', keyLabel(revision.signer, 'not a signature predicate key')),
    line('  Passes to', passesToLabel(revision)),
    line('  Certified at', `${formatIso(revision.referenceTime)}  (reference time ${revision.referenceTime})`),
    line('  Round', `${revision.roundNumber}  (round timestamp ${revision.roundTimestamp}, epoch ${revision.epoch})`),
  ];
}

function lineageLines(description: ILineageDescription): string[] {
  const lines = [
    line('Token type', 'document lineage'),
    line('Network', networkLabel(description.token.networkId.id)),
    line('Token id', HexConverter.encode(description.token.id.bytes)),
    line('Issuer', keyLabel(description.issuer, 'unreadable genesis reason')),
    line('Revisions', String(description.revisions.length)),
    line(
      'Next producer',
      keyLabel(latestNextProducer(description), description.finalized ? FINALIZED_LABEL : 'not a signature predicate'),
    ),
  ];
  description.revisions.forEach((revision, position) => {
    lines.push('', ...lineageRevisionLines(revision, position));
  });
  return lines;
}

// As for timestamps, relies on `verifyLineage` failing closed: an OK result with
// no comparison can only mean no digest was given.
function lineageExpectedHashLabel(result: ILineageVerificationResult): string {
  const matching = result.matchingRevisions;
  if (matching === null) {
    return result.status === 'OK'
      ? 'not checked; pass --file or --hash to find your document in the lineage'
      : 'not checked; verification failed';
  }
  const latest = result.description.revisions.length - 1;
  const last = matching.at(-1);
  if (last === undefined) {
    return 'differs from every revision';
  }
  const which = `matches revision${matching.length > 1 ? 's' : ''} ${matching.join(', ')}`;
  if (last !== latest) {
    return `${which}; superseded by revision ${latest}`;
  }
  return `${which} (the ${result.description.finalized ? 'final' : 'latest'})`;
}

/**
 * @param {ILineageVerificationResult} result Lineage verification outcome.
 * @param {TrustBaseSource|null} source Root of trust the verdict was produced against.
 * @returns {string} Human summary of a lineage verification, with the SDK result tree on failure.
 */
export function lineageVerifyText(result: ILineageVerificationResult, source: TrustBaseSource | null): string {
  const against = source?.kind === 'bundled' ? `the bundled ${source.network} trust base` : `${source?.path}`;
  const lines = [
    line(
      'Status',
      result.status === 'OK'
        ? `OK  (inclusion proofs, consensus signatures, issuer signature and revision chain verified against ${against})`
        : `FAIL: ${result.reason ?? 'verification failed'}`,
    ),
    line('Trust base', trustBaseLabel(source)),
    line('Expected hash', lineageExpectedHashLabel(result)),
    ...lineageLines(result.description),
  ];
  if (result.status !== 'OK' && result.details !== null) {
    lines.push('', result.details.toString());
  }
  return lines.join('\n');
}

/**
 * @param {ILineageDescription} description Fields read off a lineage token.
 * @returns {string} Human dump of a lineage token with no verification performed.
 */
export function lineageInspectText(description: ILineageDescription): string {
  return [
    line('UNVERIFIED', 'fields read from the token; nothing below has been checked'),
    ...lineageLines(description),
  ].join('\n');
}

function lineageRevisionJson(revision: ILineageRevisionDescription): ILineageRevisionJson {
  return {
    error: revision.error,
    hash: revision.digest === null ? null : { algorithm: 'SHA-256', digest: HexConverter.encode(revision.digest) },
    index: revision.index === null ? null : revision.index.toString(),
    nextProducer: revision.nextProducer === null ? null : HexConverter.encode(revision.nextProducer),
    referenceTime: revision.referenceTime.toString(),
    referenceTimeIso: toIso(revision.referenceTime),
    round: {
      epoch: revision.epoch.toString(),
      number: revision.roundNumber.toString(),
      timestamp: revision.roundTimestamp.toString(),
    },
    sealed: revision.sealed,
    signer: revision.signer === null ? null : HexConverter.encode(revision.signer),
  };
}

/**
 * @param {ILineageDescription} description Fields read off a lineage token.
 * @returns {ILineageDescriptionJson} JSON-safe fields; big integers as decimal strings.
 */
export function lineageDescriptionJson(description: ILineageDescription): ILineageDescriptionJson {
  const networkId = description.token.networkId.id;
  const nextProducer = latestNextProducer(description);
  return {
    finalized: description.finalized,
    issuer: description.issuer === null ? null : HexConverter.encode(description.issuer),
    network: { id: networkId, name: networkName(networkId) },
    nextProducer: nextProducer === null ? null : HexConverter.encode(nextProducer),
    revisions: description.revisions.map((revision) => lineageRevisionJson(revision)),
    tokenId: HexConverter.encode(description.token.id.bytes),
    tokenType: 'lineage',
  };
}

export function lineageVerifyJson(
  result: ILineageVerificationResult,
  source: TrustBaseSource | null,
): ILineageVerifyJson {
  return {
    command: 'verify',
    expectedHashMatches: result.matchingRevisions === null ? null : result.matchingRevisions.length > 0,
    matchingRevisions: result.matchingRevisions,
    reason: result.reason,
    status: result.status,
    ...lineageDescriptionJson(result.description),
    details: result.details ? resultTreeJson(result.details) : null,
    trustBase: trustBaseJson(source),
  };
}

export function lineageInspectJson(description: ILineageDescription): ILineageInspectJson {
  return { command: 'inspect', verified: false, ...lineageDescriptionJson(description) };
}
