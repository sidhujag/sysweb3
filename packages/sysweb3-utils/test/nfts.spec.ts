import { JsonRpcProvider } from 'ethers';

import {
  getERC1155StandardBalance,
  getERC721StandardBalance,
} from '../src/tokens';

describe('ERC-721 NFts tests', () => {
  it('should return balance 0 from NFT contract', async () => {
    const RpcProvider = new JsonRpcProvider();
    const erc721Balance = await getERC721StandardBalance(
      '0x0c702F78b889f25E3347fb978345F7eCF4F3861C', // Contract Address in Mumbai
      '0x6a92eF94F6Db88098625a30396e0fde7255E97d5', // Wallet Adress
      RpcProvider
    );

    expect(typeof erc721Balance).toBe('number');
    expect(erc721Balance).toBeLessThanOrEqual(0);
  });

  it('should return balance greater or equal to 1 from NFT contract', async () => {
    const RpcProvider = new JsonRpcProvider();
    const erc721Balance = await getERC721StandardBalance(
      '0xd19018f7946D518D316BB10FdFF118C28835cF7a', // Contract Address in Mumbai
      '0x6a92eF94F6Db88098625a30396e0fde7255E97d5', // Wallet Adress
      RpcProvider
    );

    expect(typeof erc721Balance).toBe('number');
    expect(erc721Balance).toBeGreaterThanOrEqual(1);
  });

  it('should preserve exact ERC-1155 balances', async () => {
    const RpcProvider = new JsonRpcProvider();
    const erc1155Balance = await getERC1155StandardBalance(
      '0xAa54A8E8BdEA1aa7E2ed7E5F681c798a8ed7e5AB',
      '0x6a92eF94F6Db88098625a30396e0fde7255E97d5',
      RpcProvider,
      1
    );

    expect(erc1155Balance).toBe('1000000000000000001');
    expect(typeof erc1155Balance).toBe('string');
  });
});
