import {
  CHAIN_ID_HEX,
  CHAIN_ID_NUMBER,
  RPC_URL,
  VALID_ETH_RPC_RESPONSE,
} from './constants';
import * as networkSdk from '../src';
import {
  isValidChainIdForEthNetworks,
  validateChainId,
  validateEvmRpcBatch,
  validateEthRpc,
} from '../src/rpc';
import 'isomorphic-fetch';

describe('rpc tests', () => {
  it('should check if given chain id is a safe integer and it is between 0 and 4503599627370476', () => {
    const isValid = isValidChainIdForEthNetworks(CHAIN_ID_NUMBER);

    expect(isValid).toBe(true);
  });

  it('should validate an ethereum chain id', () => {
    const isValid = validateChainId(CHAIN_ID_NUMBER);

    expect(isValid.valid).toBe(true);
    expect(isValid.hexChainId).toBe(CHAIN_ID_HEX);
  });

  it('should validate given eth rpc', async () => {
    const response = await validateEthRpc(RPC_URL, false);

    expect(response).toStrictEqual(VALID_ETH_RPC_RESPONSE);
  });
});

describe('EVM endpoint latency probe', () => {
  afterEach(() => {
    jest.restoreAllMocks();
    jest.useRealTimers();
  });

  it('samples the existing two-method EVM batch and checks the selected chain', async () => {
    jest.useFakeTimers();
    const read = jest.spyOn(globalThis, 'fetch').mockImplementation(
      async () =>
        new Response(
          JSON.stringify([
            { jsonrpc: '2.0', id: 1, result: '0x539' },
            { jsonrpc: '2.0', id: 2, result: '0x2' },
          ])
        )
    );
    const endpoint = 'https://evm-catalogue-probe.invalid/';
    const result = validateEvmRpcBatch(endpoint, 1337);
    await jest.runAllTimersAsync();
    await expect(result).resolves.toMatchObject({
      success: true,
      chainId: 1337,
    });
    const samples = read.mock.calls.filter(([url]) => url === endpoint);
    expect(samples).toHaveLength(3);
    for (const [, options] of samples) {
      expect(options?.method).toBe('POST');
      expect(JSON.parse(String(options?.body))).toMatchObject([
        { method: 'eth_chainId', id: 1 },
        { method: 'eth_blockNumber', id: 2 },
      ]);
    }
  });

  it('exposes no status-only UTXO probe through the package entry', () => {
    expect('validateRpcBatchUniversal' in networkSdk).toBe(false);
  });
});
