import {
  clearRpcCaches,
  coins,
  findUtxoCoinByRegistration,
  getSysRpc,
  observeSysRpc,
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

it('requires verification ownership before reading an endpoint', async () => {
  const read = status({ network: 'tSYS', coin: 'Syscoin Testnet' }, 'test');
  await expect(
    Reflect.apply(getSysRpc, undefined, [{ url: endpoint }])
  ).rejects.toThrow('Invalid UTXO registration verification');
  expect(read).not.toHaveBeenCalled();
});

function ownedRead(
  registration: { chainId: number; slip44: number },
  coinName: string,
  backendChain: string
) {
  const coin = findUtxoCoinByRegistration(registration)!;
  return {
    registration,
    backendChain,
    signal: new AbortController().signal,
    assertCurrent: () => undefined,
    readJson: jest.fn(async (url: string) => {
      if (url === `${endpoint}api/v2/`)
        return {
          blockbook: { coin: coinName },
          backend: { chain: backendChain },
        };
      expect(url).toBe(`${endpoint}api/v2/block-index/0`);
      return { blockHash: coin.hashGenesisBlock };
    }),
  };
}

it('formats the same verified and first-use display fields after status and genesis', async () => {
  const owner = ownedRead(
    { chainId: 5700, slip44: 1 },
    'Syscoin Testnet',
    'test'
  );
  const draft = { url: endpoint, label: 'My test network' };
  const verified = await getSysRpc(draft, owner);
  const observed = await observeSysRpc(draft, {
    registration: owner.registration,
    signal: owner.signal,
    assertCurrent: owner.assertCurrent,
    readJson: owner.readJson,
  });
  expect(observed).toEqual(verified);
  expect(verified).toMatchObject({
    network: 'tSYS',
    chain: 'test',
    rpc: {
      formattedNetwork: {
        chainId: 5700,
        slip44: 1,
        kind: INetworkType.Syscoin,
        label: 'My test network',
        currency: 'tsys',
        url: endpoint,
        explorer: endpoint,
        utxoBackendChain: 'test',
        default: false,
      },
      networkConfig: { networks: { testnet: { bech32: 'tsys' } } },
    },
  });
  expect(owner.readJson).toHaveBeenCalledTimes(4);
});

it('preserves a zero chain ID without treating it as a missing registration', async () => {
  const owner = ownedRead({ chainId: 0, slip44: 0 }, 'Bitcoin', 'main');
  const { rpc } = await getSysRpc({ url: endpoint }, owner);
  expect(rpc.formattedNetwork.chainId).toBe(0);
  expect(rpc.formattedNetwork.slip44).toBe(0);
  expect(rpc.networkConfig.networks.mainnet.bech32).toBe('bc');
  expect(owner.readJson).toHaveBeenCalledTimes(2);
});

it('refuses an ambiguous canonical tuple before reading the endpoint', async () => {
  const owner = ownedRead({ chainId: 2, slip44: 2 }, 'Litecoin', 'main');
  const litecoin = coins.find((coin) => coin.name === 'Litecoin')!;
  coins.push({ ...litecoin, name: 'Duplicate Litecoin Fixture' });
  await expect(getSysRpc({ url: endpoint }, owner)).rejects.toThrow(
    'Invalid UTXO registration verification'
  );
  expect(owner.readJson).not.toHaveBeenCalled();
});

it('refuses to reinterpret a verification request as first-use observation', async () => {
  const owner = ownedRead(
    { chainId: 5700, slip44: 1 },
    'Syscoin Testnet',
    'test'
  );
  await expect(
    Reflect.apply(observeSysRpc, undefined, [{ url: endpoint }, owner])
  ).rejects.toThrow('Invalid UTXO registration verification');
  expect(owner.readJson).not.toHaveBeenCalled();
});

it.each(['abort', 'stale'])(
  'refuses a %s first-use preview after the last observation guard',
  async (kind) => {
    const { backendChain, ...reader } = ownedRead(
      { chainId: 5700, slip44: 1 },
      'Syscoin Testnet',
      'test'
    );
    expect(backendChain).toBe('test');
    const controller = new AbortController();
    let guardCalls = 0;
    let current = true;
    const observed = observeSysRpc(
      { url: endpoint },
      {
        ...reader,
        signal: controller.signal,
        assertCurrent() {
          if (!current) throw new Error('Draft changed');
          if (++guardCalls === 5)
            queueMicrotask(() => {
              if (kind === 'abort') controller.abort();
              else current = false;
            });
        },
      }
    );
    await expect(observed).rejects.toThrow(
      'UTXO registration verification cancelled'
    );
    expect(reader.readJson).toHaveBeenCalledTimes(2);
  }
);
