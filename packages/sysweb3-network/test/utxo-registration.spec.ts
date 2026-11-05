import {
  clearRpcCaches,
  coins,
  findUtxoCoinByRegistration,
  getSysRpc,
  INetworkType,
} from '../src';

const endpoint = 'https://utxo-registration.invalid/';
const originalFetch = global.fetch;
const originalCoins = [...coins];

function status(blockbook: { coin: string; network?: string }, chain: string) {
  const read = jest.fn(async (url: string) => {
    expect(url).toBe(`${endpoint}api/v2`);
    return { ok: true, json: async () => ({ blockbook, backend: { chain } }) };
  });
  global.fetch = read as unknown as typeof global.fetch;
  return read;
}

beforeEach(() => clearRpcCaches());
afterEach(() => {
  global.fetch = originalFetch;
  coins.splice(0, coins.length, ...originalCoins);
});

it('resolves exact canonical UTXO coordinates without consulting display text', () => {
  expect(findUtxoCoinByRegistration({ chainId: 0, slip44: 0 })?.name).toBe(
    'Bitcoin'
  );
  const testnet = {
    chainId: 5700,
    slip44: 1,
    label: 'Regtest',
    currency: 'regtest',
  };
  expect(findUtxoCoinByRegistration(testnet)?.name).toBe('Syscoin Testnet');
  expect(findUtxoCoinByRegistration({ chainId: 10000, slip44: 1 })?.name).toBe(
    'Regtest'
  );
  expect(
    findUtxoCoinByRegistration({ chainId: 5700, slip44: 57 })
  ).toBeUndefined();
  expect(
    findUtxoCoinByRegistration({ chainId: 999, slip44: 1 })
  ).toBeUndefined();
});

it('preserves the RPC preview and display fields for a known status alias', async () => {
  const read = status({ network: 'tSYS', coin: 'Syscoin Testnet' }, 'test');
  const result = await getSysRpc({
    url: endpoint,
    label: 'My test network',
    symbol: 'CUSTOM',
  });
  expect(result).toMatchObject({
    network: 'tSYS',
    chain: 'test',
    rpc: {
      formattedNetwork: {
        chainId: 5700,
        slip44: 1,
        kind: INetworkType.Syscoin,
        label: 'My test network',
        currency: 'custom',
        url: endpoint,
        explorer: endpoint,
        default: false,
      },
      networkConfig: { networks: { testnet: { bech32: 'tsys' } } },
    },
  });
  expect(read).toHaveBeenCalledTimes(1);
});

it('preserves an explicit zero chain ID independent of SLIP44 in the RPC result', async () => {
  const name = 'Explicit Zero Fixture';
  const litecoin = coins.find((coin) => coin.name === 'Litecoin')!;
  coins.push({
    ...litecoin,
    chainId: 0,
    name,
    coinName: name,
    coinLabel: name,
  });
  const read = status({ coin: name }, 'main');
  const { rpc } = await getSysRpc({ url: endpoint });
  expect(rpc.formattedNetwork.chainId).toBe(0);
  expect(rpc.formattedNetwork.slip44).toBe(litecoin.slip44);
  expect(rpc.networkConfig.networks.mainnet.bech32).toBe('ltc');
  expect(read).toHaveBeenCalledTimes(1);
});

it('refuses to build RPC configuration for an ambiguous canonical tuple', async () => {
  const litecoin = coins.find((coin) => coin.name === 'Litecoin')!;
  coins.push({ ...litecoin, name: 'Duplicate Litecoin Fixture' });
  const read = status({ coin: 'Litecoin', network: 'LTC' }, 'main');
  await expect(getSysRpc({ url: endpoint })).rejects.toThrow(
    'Invalid canonical UTXO coin registration'
  );
  expect(read).toHaveBeenCalledTimes(1);
});
