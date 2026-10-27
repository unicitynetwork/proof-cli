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

/**
 * Overrides for {@link resolveNetwork}.
 *
 * A replacement trust base arrives already parsed. This module reads no files, so
 * the verification path can run where there is no filesystem; turning a
 * `--trust-base` path into a trust base is the CLI's job.
 */
export interface INetworkOverrides {
  /** Overrides the preset gateway. */
  readonly gatewayUrl?: string;
  /** Defaults to mainnet. */
  readonly network?: NetworkName;
  /** Replaces the bundled trust base. */
  readonly trustBase?: RootTrustBase;
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
 * Resolve gateway and trust base from a preset plus optional overrides.
 *
 * @param {INetworkOverrides} overrides Gateway, preset and trust base overrides.
 * @returns {ITimestampNetwork} Resolved network.
 */
export function resolveNetwork(overrides: INetworkOverrides = {}): ITimestampNetwork {
  const name = overrides.network ?? 'mainnet';
  return {
    gatewayUrl: overrides.gatewayUrl ?? NETWORKS[name].gatewayUrl,
    preset: name,
    trustBase: overrides.trustBase ?? bundledTrustBase(name),
  };
}
