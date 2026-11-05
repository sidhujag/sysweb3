import {
  CHAIN_ID_HEX,
  CHAIN_ID_NUMBER,
  RPC_URL,
  VALID_ETH_RPC_RESPONSE,
} from './constants';
import {
  isValidChainIdForEthNetworks,
  validateChainId,
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
