import {
  clearRpcCaches,
  coins,
  findCoin,
  findUtxoCoinByRegistration,
  getNetworkConfig,
  getSysRpc,
  validateSysRpc,
} from '../src';

import type { OwnedUtxoRpcVerification } from '../src';

const url = 'https://blockbook.invalid/tenant/?access=public%2Bfixture';
const statusUrl =
  'https://blockbook.invalid/tenant/api/v2/?access=public%2Bfixture';
const genesisUrl =
  'https://blockbook.invalid/tenant/api/v2/block-index/0?access=public%2Bfixture';
const SYS_TEST = { chainId: 5700, slip44: 1 };
const BTC = { chainId: 0, slip44: 0 };
const BTG = { chainId: 156, slip44: 156 };
const legacy = { blockbook: { coin: 'Syscoin' }, backend: { chain: 'test' } };
const modern = {
  blockbook: { coin: 'Syscoin Testnet', network: 'tSYS', decimals: 8 },
  backend: { chain: 'test', error: '' },
};
const genesis = (registration: OwnedUtxoRpcVerification['registration']) => ({
  blockHash: findUtxoCoinByRegistration(registration)!.hashGenesisBlock,
});
const mismatch = 'UTXO registration does not match the selected coin';
const cancelled = 'UTXO registration verification cancelled';
const invalid = 'Invalid UTXO registration verification';
const originalFetch = global.fetch;
const originalCoins = [...coins];
let ambient: jest.Mock;

beforeEach(() => {
  clearRpcCaches();
  ambient = jest.fn(async () => {
    throw new Error('Unexpected ambient fetch');
  });
  global.fetch = ambient;
});
afterEach(() => {
  expect(ambient).not.toHaveBeenCalled();
  global.fetch = originalFetch;
  coins.splice(0, coins.length, ...originalCoins);
});

function verification(status: unknown, block: unknown = genesis(SYS_TEST)) {
  const controller = new AbortController();
  const readJson = jest.fn(async (requested: string, signal: AbortSignal) => {
    expect(signal).toBe(controller.signal);
    if (requested === statusUrl) return status;
    if (requested === genesisUrl) return block;
    throw new Error('Unexpected route');
  });
  const owner = {
    assertCurrent: () => undefined,
    backendChain: 'test',
    readJson,
    registration: { ...SYS_TEST },
    signal: controller.signal,
  } satisfies OwnedUtxoRpcVerification;
  return { owner, controller, readJson };
}

it.each([legacy, modern])(
  'preserves the selected testnet identity through the existing custody lookup',
  async (status) => {
    const { owner, readJson } = verification(status);
    const result = await getSysRpc(
      {
        url,
        label: 'Custom name',
        symbol: 'REGTEST',
        explorer: 'https://explorer.invalid/',
      },
      owner
    );
    expect(result).toMatchObject({
      network: 'tSYS',
      chain: 'test',
      rpc: {
        formattedNetwork: {
          chainId: 5700,
          slip44: 1,
          currency: 'tsys',
          label: 'Custom name',
          url,
          explorer: 'https://explorer.invalid/',
        },
        networkConfig: { networks: { testnet: { bech32: 'tsys' } } },
      },
    });
    const { slip44, currency } = result.rpc.formattedNetwork;
    expect(getNetworkConfig(slip44, currency)).toEqual(
      result.rpc.networkConfig
    );
    expect(findCoin({ slip44, name: currency, exactMatch: true })).toBe(
      findUtxoCoinByRegistration(SYS_TEST)
    );
    expect(readJson.mock.calls).toEqual([
      [statusUrl, owner.signal],
      [genesisUrl, owner.signal],
    ]);
  }
);

it('verifies Bitcoin chain zero on its own identity despite sharing genesis with Bitcoin Gold', async () => {
  expect(genesis(BTC)).toEqual(genesis(BTG));
  const { owner, readJson } = verification(
    {
      blockbook: { coin: 'Bitcoin', network: 'BTC', decimals: 8 },
      backend: { chain: 'main' },
    },
    genesis(BTC)
  );
  const result = await getSysRpc(
    { url },
    { ...owner, registration: BTC, backendChain: 'main' }
  );
  expect(result).toMatchObject({
    network: 'BTC',
    rpc: { formattedNetwork: { chainId: 0, slip44: 0, currency: 'btc' } },
  });
  expect(readJson).toHaveBeenCalledTimes(2);
  readJson.mockClear();
  await expect(
    getSysRpc({ url }, { ...owner, registration: BTG, backendChain: 'main' })
  ).rejects.toThrow(mismatch);
  expect(readJson.mock.calls).toEqual([[statusUrl, owner.signal]]);
});

it.each([true, false])(
  'rejects a same-SLIP44 legacy lookup alias collision before reading (competitor first: %s)',
  async (first) => {
    const regtest = findUtxoCoinByRegistration({ chainId: 10000, slip44: 1 })!;
    const competitor = { ...regtest, coinName: 'TSYS' };
    const at = coins.indexOf(regtest);
    coins.splice(at, 1);
    if (first) coins.unshift(competitor);
    else coins.push(competitor);
    const { owner, readJson } = verification(modern);
    await expect(getSysRpc({ url }, owner)).rejects.toThrow(invalid);
    expect(readJson).not.toHaveBeenCalled();
  }
);

it('does not read an editable symbol in owned mode', async () => {
  const { owner } = verification(modern);
  const get = jest.fn(() => 'REGTEST');
  const draft = Object.defineProperty({ url, label: 'Custom name' }, 'symbol', {
    get,
  });
  const { rpc } = await getSysRpc(draft, owner);
  expect(rpc.formattedNetwork).toMatchObject({
    currency: 'tsys',
    label: 'Custom name',
  });
  expect(get).not.toHaveBeenCalled();
});

it.each([
  {
    blockbook: { network: 'tSYS', coin: 'Bitcoin' },
    backend: { chain: 'test' },
  },
  {
    blockbook: { network: 'Syscoin', coin: 'Syscoin Testnet' },
    backend: { chain: 'test' },
  },
  {
    blockbook: { network: 'SYS', coin: 'Syscoin' },
    backend: { chain: 'test' },
  },
  {
    blockbook: { network: 'tSYS', coin: 'Syscoin Testnet' },
    backend: { chain: 'main' },
  },
  { blockbook: { network: 'tSYS', decimals: 18 }, backend: { chain: 'test' } },
])('refuses contradictory status before genesis', async (status) => {
  const { owner, readJson } = verification(status);
  await expect(getSysRpc({ url }, owner)).rejects.toThrow(mismatch);
  expect(readJson.mock.calls).toEqual([[statusUrl, owner.signal]]);
});

it('refuses wrong genesis and an ambiguous legacy identity even with matching genesis', async () => {
  const wrong = verification(legacy, genesis({ chainId: 57, slip44: 57 }));
  await expect(getSysRpc({ url }, wrong.owner)).rejects.toThrow(mismatch);
  expect(wrong.readJson).toHaveBeenCalledTimes(2);
  const selected = findUtxoCoinByRegistration(SYS_TEST)!;
  coins.push({
    ...selected,
    chainId: 12345,
    name: 'Other test coin',
    coinShortcut: 'OTHER',
    shortcut: 'OTHER',
  });
  const ambiguous = verification(legacy);
  await expect(getSysRpc({ url }, ambiguous.owner)).rejects.toThrow(mismatch);
  expect(ambiguous.readJson).toHaveBeenCalledTimes(2);
});

it('refuses invalid registration, endpoints and asynchronous guards before reading', async () => {
  const { owner, readJson } = verification(modern);
  await expect(
    getSysRpc(
      { url },
      { ...owner, registration: { chainId: 5700, slip44: 57 } }
    )
  ).rejects.toThrow(invalid);
  await expect(
    getSysRpc({ url }, null as unknown as OwnedUtxoRpcVerification)
  ).rejects.toThrow(invalid);
  for (const endpoint of [
    'file:///wallet',
    'https://user:secret@blockbook.invalid/',
    'https://blockbook.invalid/#fragment',
    'https://[bad',
  ]) {
    await expect(getSysRpc({ url: endpoint }, owner)).rejects.toThrow(invalid);
  }
  await expect(getSysRpc({ url, label: {} }, owner)).rejects.toThrow(
    'Invalid UTXO registration draft'
  );
  await expect(
    getSysRpc(
      { url },
      {
        ...owner,
        assertCurrent: async () => {
          throw new Error('late guard');
        },
      }
    )
  ).rejects.toThrow(invalid);
  expect(readJson).not.toHaveBeenCalled();
});

it('does not invoke status accessors or accept a genesis response with an error', async () => {
  const get = jest.fn(() => 'tSYS');
  const accessor = verification({
    blockbook: Object.defineProperty({ coin: 'Syscoin Testnet' }, 'network', {
      get,
    }),
    backend: { chain: 'test' },
  });
  await expect(getSysRpc({ url }, accessor.owner)).rejects.toThrow(invalid);
  expect(accessor.readJson).toHaveBeenCalledTimes(1);
  expect(get).not.toHaveBeenCalled();
  const errored = verification(modern, {
    ...genesis(SYS_TEST),
    error: 'fixture',
  });
  await expect(getSysRpc({ url }, errored.owner)).rejects.toThrow(invalid);
  expect(errored.readJson).toHaveBeenCalledTimes(2);
});

it('cancels before dispatch, after status, and after an owner change during genesis', async () => {
  const already = verification(modern);
  already.controller.abort();
  await expect(getSysRpc({ url }, already.owner)).rejects.toThrow(cancelled);
  expect(already.readJson).not.toHaveBeenCalled();

  const duringStatus = verification(modern);
  duringStatus.readJson.mockImplementationOnce(async () => {
    duringStatus.controller.abort();
    return modern;
  });
  await expect(getSysRpc({ url }, duringStatus.owner)).rejects.toThrow(
    cancelled
  );
  expect(duringStatus.readJson).toHaveBeenCalledTimes(1);

  const duringGenesis = verification(modern);
  let current = true;
  duringGenesis.readJson
    .mockImplementationOnce(async () => modern)
    .mockImplementationOnce(async () => {
      current = false;
      return genesis(SYS_TEST);
    });
  await expect(
    getSysRpc(
      { url },
      {
        ...duringGenesis.owner,
        assertCurrent() {
          if (!current) throw new Error('scope changed');
        },
      }
    )
  ).rejects.toThrow(cancelled);
  expect(duringGenesis.readJson).toHaveBeenCalledTimes(2);
});

it('never trusts ambient cached status or echoes an owned transport failure', async () => {
  const oldStatus = jest.fn(async () => ({
    ok: true,
    json: async () => modern,
  }));
  global.fetch = oldStatus as unknown as typeof global.fetch;
  await expect(validateSysRpc(url)).resolves.toMatchObject({ valid: true });
  expect(oldStatus).toHaveBeenCalledTimes(1);
  global.fetch = ambient;
  const { owner, readJson } = verification(modern);
  readJson.mockRejectedValueOnce(new Error('private fixture diagnostic'));
  await expect(getSysRpc({ url }, owner)).rejects.toThrow(
    /^UTXO registration read failed$/
  );
  expect(readJson.mock.calls).toEqual([[statusUrl, owner.signal]]);
});

it('captures the same draft, endpoint, profile and owned transport before awaiting status', async () => {
  const draft = {
    url,
    label: 'Initial display',
    symbol: 'tSYS',
    explorer: 'https://explorer.invalid/',
  };
  const { owner, readJson } = verification(modern);
  const wrongRead = jest.fn();
  let release!: () => void;
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const entered = new Promise<void>((resolve) => {
    readJson.mockImplementationOnce(async () => {
      resolve();
      await held;
      return modern;
    });
  });
  const signal = owner.signal;
  const pending = getSysRpc(draft, owner);
  await entered;
  Object.assign(draft, {
    url: 'https://different.invalid',
    label: 'Different',
    symbol: 'BTC',
    explorer: 'https://different.invalid/explorer',
  });
  Object.assign(owner, {
    backendChain: 'main',
    readJson: wrongRead,
    registration: BTC,
  });
  release();
  await expect(pending).resolves.toMatchObject({
    network: 'tSYS',
    chain: 'test',
    rpc: {
      formattedNetwork: {
        url,
        label: 'Initial display',
        currency: 'tsys',
        explorer: 'https://explorer.invalid/',
        chainId: 5700,
      },
    },
  });
  expect(wrongRead).not.toHaveBeenCalled();
  expect(readJson.mock.calls).toEqual([
    [statusUrl, signal],
    [genesisUrl, signal],
  ]);
});
