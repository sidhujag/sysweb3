import { Interface } from 'ethers';

import {
  fetchStandardTokenMetadata,
  getNftStandardMetadata,
} from '../src/tokens';

const iface = new Interface([
  'function supportsInterface(bytes4) view returns(bool)',
  'function decimals() view returns(uint8)',
  'function symbol() view returns(string)',
  'function name() view returns(string)',
]);
const address = '0x' + '11'.repeat(20);
function runner() {
  const methods: string[] = [];
  return {
    methods,
    call: async (request: { data?: string }) => {
      const parsed = iface.parseTransaction({ data: request.data! })!;
      methods.push(parsed.name);
      return iface.encodeFunctionResult(parsed.name, [
        parsed.name === 'decimals'
          ? 18
          : parsed.name === 'supportsInterface'
          ? true
          : 'TOKEN',
      ]);
    },
  };
}
it('reads ERC20 metadata without holder balance', async () => {
  const provider = runner();
  await expect(fetchStandardTokenMetadata(address, provider)).resolves.toEqual({
    decimals: 18,
    tokenSymbol: 'TOKEN',
  });
  expect(provider.methods.sort()).toEqual(['decimals', 'symbol']);
});
it.each(['ERC-721', 'ERC-1155'] as const)(
  'reuses same-phase verified %s type for NFT metadata',
  async (type) => {
    const provider = runner();
    await expect(
      getNftStandardMetadata(address, provider, type)
    ).resolves.toEqual({ name: 'TOKEN', symbol: 'TOKEN' });
    expect(provider.methods).toEqual(['name', 'symbol']);
  }
);
it('retains classification for callers without a verified type', async () => {
  const provider = runner();
  await getNftStandardMetadata(address, provider);
  expect(provider.methods).toEqual(['supportsInterface', 'name', 'symbol']);
});
