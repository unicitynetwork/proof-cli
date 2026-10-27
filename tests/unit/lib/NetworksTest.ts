import {
  bundledTrustBase,
  isNetworkName,
  NETWORK_NAMES,
  networkNameForId,
  NETWORKS,
  resolveNetwork,
} from '../../../src/lib/networks.js';

describe('networks', () => {
  it('knows mainnet and testnet2 with the documented gateways and ids', () => {
    expect(NETWORK_NAMES).toEqual(['mainnet', 'testnet2']);
    expect(NETWORKS.mainnet.gatewayUrl).toEqual('https://gateway.mainnet.unicity.network');
    expect(NETWORKS.mainnet.networkId).toBe(1);
    expect(NETWORKS.testnet2.gatewayUrl).toEqual('https://gateway.testnet2.unicity.network');
    expect(NETWORKS.testnet2.networkId).toBe(4);
  });

  it('bundles trust bases whose network ids match the presets', () => {
    expect(bundledTrustBase('mainnet').networkId.id).toBe(1);
    expect(bundledTrustBase('testnet2').networkId.id).toBe(4);
    expect(bundledTrustBase('mainnet').rootNodes.size).toBeGreaterThan(0);
  });

  it('looks network names up by id', () => {
    expect(networkNameForId(1)).toEqual('mainnet');
    expect(networkNameForId(4)).toEqual('testnet2');
    expect(networkNameForId(3)).toBeUndefined();
  });

  it('recognises network names and nothing else', () => {
    expect(isNetworkName('mainnet')).toBe(true);
    expect(isNetworkName('testnet2')).toBe(true);
    expect(isNetworkName('testnet')).toBe(false);
    expect(isNetworkName('hasOwnProperty')).toBe(false);
    expect(isNetworkName('')).toBe(false);
  });

  it('resolves mainnet by default and applies overrides', () => {
    const byDefault = resolveNetwork();
    expect(byDefault.preset).toEqual('mainnet');
    expect(byDefault.gatewayUrl).toEqual(NETWORKS.mainnet.gatewayUrl);
    expect(byDefault.trustBase.networkId.id).toBe(1);

    const overridden = resolveNetwork({
      gatewayUrl: 'http://localhost:3000',
      network: 'mainnet',
      trustBase: bundledTrustBase('testnet2'),
    });
    expect(overridden.preset).toEqual('mainnet');
    expect(overridden.gatewayUrl).toEqual('http://localhost:3000');
    expect(overridden.trustBase.networkId.id).toBe(4);
  });
});
