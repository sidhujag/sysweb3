jest.unmock('ethers');
jest.unmock('ethers/contract');

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
function runner(failures: Partial<Record<'name' | 'symbol', Error>> = {}) {
  const methods: string[] = [];
  return {
    methods,
    call: async (request: { data?: string }) => {
      const parsed = iface.parseTransaction({ data: request.data! })!;
      methods.push(parsed.name);
      if (failures[parsed.name as 'name' | 'symbol'])
        throw failures[parsed.name as 'name' | 'symbol'];
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

const transportFailure = () =>
  Object.assign(new Error('Temporary public RPC failure'), {
    code: 'NETWORK_ERROR',
  });

it.each(['ERC-721', 'ERC-1155'] as const)(
  'preserves transient optional metadata failure provenance for %s',
  async (type) => {
    const provider = runner({
      name: transportFailure(),
      symbol: transportFailure(),
    });
    await expect(
      getNftStandardMetadata(address, provider, type)
    ).resolves.toEqual({
      name: `${type} Collection`,
      symbol: 'NFT',
      metadataUnavailable: true,
    });
    expect(provider.methods).toEqual(['name', 'symbol']);
  }
);

it.each(['name', 'symbol'] as const)(
  'keeps a healthy optional field when %s temporarily fails',
  async (field) => {
    await expect(
      getNftStandardMetadata(
        address,
        runner({ [field]: transportFailure() }),
        'ERC-721'
      )
    ).resolves.toEqual({
      name: 'TOKEN',
      symbol: field === 'symbol' ? 'NFT' : 'TOKEN',
      metadataUnavailable: true,
    });
  }
);

it.each([
  Object.assign(new Error('Optional method is not implemented'), {
    code: 'CALL_EXCEPTION',
    data: '0x',
  }),
  Object.assign(new Error('Optional method returns no data'), {
    code: 'BAD_DATA',
    value: '0x',
  }),
])('keeps legitimate optional-method absence cacheable', async (error) => {
  await expect(
    getNftStandardMetadata(
      address,
      runner({ name: error, symbol: error }),
      'ERC-1155'
    )
  ).resolves.toEqual({
    name: 'ERC-1155 Collection',
    symbol: 'NFT',
  });
});

it('does not consume cancellation as optional metadata absence', async () => {
  const cancelled = Object.assign(new Error('cancelled'), {
    name: 'AbortError',
  });
  const provider = runner({ name: cancelled });
  await expect(
    getNftStandardMetadata(address, provider, 'ERC-721')
  ).rejects.toBe(cancelled);
  expect(provider.methods).toEqual(['name']);
});

it.each([
  Object.assign(new Error('rate limited'), { code: 'SERVER_ERROR' }),
  Object.assign(new Error('malformed metadata'), {
    code: 'BAD_DATA',
    value: '0x1234',
  }),
  Object.assign(new Error('temporary custom revert'), {
    code: 'CALL_EXCEPTION',
    data: '0x12345678',
  }),
])(
  'does not mark other optional-field failures as permanent absence',
  async (error) => {
    await expect(
      getNftStandardMetadata(address, runner({ name: error }), 'ERC-721')
    ).resolves.toMatchObject({
      name: 'TOKEN',
      symbol: 'TOKEN',
      metadataUnavailable: true,
    });
  }
);

it.each(['name', 'symbol'] as const)(
  'keeps partial legitimate absence cacheable (%s)',
  async (field) => {
    const error = Object.assign(new Error('Not implemented'), {
      code: 'CALL_EXCEPTION',
      data: '0x',
    });
    await expect(
      getNftStandardMetadata(address, runner({ [field]: error }), 'ERC-721')
    ).resolves.toEqual({
      name: 'TOKEN',
      symbol: field === 'symbol' ? 'NFT' : 'TOKEN',
    });
  }
);
