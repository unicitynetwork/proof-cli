import { readFile } from 'node:fs/promises';

import { RootTrustBase } from '@unicitylabs/state-transition-sdk/lib/api/bft/RootTrustBase.js';

import mainnetTrustBase from '../trust-bases/bft-trustbase.mainnet.json' with { type: 'json' };
import testnet2TrustBase from '../trust-bases/bft-trustbase.testnet2.json' with { type: 'json' };

/** A known network: its gateway and its pinned trust base. */
export interface INetworkPreset {
  readonly gatewayUrl: string;
  readonly networkId: number;
  readonly trustBaseJson: unknown;
}

export const NETWORKS = {
  mainnet: {
    gatewayUrl: 'https://gateway.mainnet.unicity.network',
    networkId: 1,
    trustBaseJson: mainnetTrustBase,
  },
  testnet2: {
    gatewayUrl: 'https://gateway.testnet2.unicity.network',
    networkId: 4,
    trustBaseJson: testnet2TrustBase,
  },
} as const satisfies Record<string, INetworkPreset>;

export type NetworkName = keyof typeof NETWORKS;

export const NETWORK_NAMES = Object.keys(NETWORKS) as readonly NetworkName[];

/** Where a stamp goes and what verifies it. */
export interface ITimestampNetwork {
  readonly gatewayUrl: string;
  /** Preset the selection started from, even when the gateway or trust base was overridden. */
  readonly preset: NetworkName;
  readonly trustBase: RootTrustBase;
}

export interface INetworkSelection {
  /** Overrides the preset gateway. */
  readonly gatewayUrl?: string;
  /** Defaults to mainnet. */
  readonly network?: NetworkName;
  /** Path to a trust base JSON file that replaces the bundled one. */
  readonly trustBasePath?: string;
}

/**
 * Where the root of trust came from. A union rather than a pair of optional
 * fields, so a reader cannot be handed a bundled network name and a file path at
 * once and have to guess which one was used.
 */
export type TrustBaseSource =
  { readonly kind: 'bundled'; readonly network: NetworkName } | { readonly kind: 'file'; readonly path: string };

/** A trust base together with where it came from. */
export interface ITrustBaseChoice {
  readonly source: TrustBaseSource;
  readonly trustBase: RootTrustBase;
}

/**
 * @param {string} value Candidate name.
 * @returns {boolean} True if the value names a bundled network.
 */
export function isNetworkName(value: string): value is NetworkName {
  return Object.hasOwn(NETWORKS, value);
}

/**
 * @param {number} networkId Network id as carried by a token or trust base.
 * @returns {NetworkName|undefined} The bundled network with that id, if any.
 */
export function networkNameForId(networkId: number): NetworkName | undefined {
  return NETWORK_NAMES.find((name) => NETWORKS[name].networkId === networkId);
}

/**
 * @param {NetworkName} name Bundled network.
 * @returns {RootTrustBase} Its pinned trust base.
 */
export function bundledTrustBase(name: NetworkName): RootTrustBase {
  return RootTrustBase.fromJSON(NETWORKS[name].trustBaseJson);
}

/**
 * Read and parse a trust base file.
 *
 * @param {string} path File path.
 * @returns {Promise<RootTrustBase>} Parsed trust base.
 * @throws {Error} If the file cannot be read or is not a trust base.
 */
export async function loadTrustBase(path: string): Promise<RootTrustBase> {
  return RootTrustBase.fromJSON(JSON.parse(await readFile(path, 'utf8')));
}

/**
 * Resolve gateway and trust base from a preset plus optional overrides.
 *
 * @param {INetworkSelection} selection Preset and overrides.
 * @returns {Promise<ITimestampNetwork>} Resolved network.
 */
export async function resolveNetwork(selection: INetworkSelection = {}): Promise<ITimestampNetwork> {
  const name = selection.network ?? 'mainnet';
  return {
    gatewayUrl: selection.gatewayUrl ?? NETWORKS[name].gatewayUrl,
    preset: name,
    trustBase: selection.trustBasePath ? await loadTrustBase(selection.trustBasePath) : bundledTrustBase(name),
  };
}
