import {
  clearRpcCaches,
  coins,
  findCoin,
  findUtxoCoinByRegistration,
  getNetworkConfig,
  getSysRpc,
} from '../src';
import { observeFirstUseUtxoRpc } from '../src/ownedUtxoRpc';

import type { OwnedUtxoRpcVerification } from '../src';
import type { OwnedUtxoRpcFirstUse } from '../src/ownedUtxoRpc';

const url = 'https://blockbook.invalid/tenant/';
const statusUrl = 'https://blockbook.invalid/tenant/api/v2/';
const genesisUrl = 'https://blockbook.invalid/tenant/api/v2/block-index/0';
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

function firstUse(status: unknown, block?: unknown) {
  const { owner, controller, readJson } = verification(status, block);
  const observation: OwnedUtxoRpcFirstUse = {
    assertCurrent: owner.assertCurrent,
    signal: owner.signal,
    readJson,
  };
  return { observation, controller, readJson };
}

it('observes an exact backend token and canonical registration without an expected token', async () => {
  const { observation, readJson } = firstUse(legacy);
  const result = await observeFirstUseUtxoRpc(url, observation);
  expect(result).toEqual({
    registration: SYS_TEST,
    coin: findUtxoCoinByRegistration(SYS_TEST),
    currency: 'tsys',
    observedBackendChain: 'test',
    assertCurrent: expect.any(Function),
  });
  expect(Object.isFrozen(result)).toBe(true);
  expect(Object.isFrozen(result.registration)).toBe(true);
  expect(Object.isFrozen(result.coin)).toBe(true);
  expect(readJson.mock.calls).toEqual([
    [statusUrl, observation.signal],
    [genesisUrl, observation.signal],
  ]);
});

it.each([
  [BTC, BTG],
  [BTG, BTC],
  [
    { chainId: 2, slip44: 2 },
    { chainId: 8, slip44: 8 },
  ],
  [
    { chainId: 8, slip44: 8 },
    { chainId: 2, slip44: 2 },
  ],
])(
  'uses reported coin identity as well as shared genesis for %j',
  async (registration, other) => {
    const coin = findUtxoCoinByRegistration(registration)!;
    expect(genesis(registration)).toEqual(genesis(other));
    const { observation, readJson } = firstUse(
      {
        blockbook: { network: coin.coinShortcut, coin: coin.coinLabel },
        backend: { chain: 'Main_Fixture' },
      },
      genesis(registration)
    );
    await expect(observeFirstUseUtxoRpc(url, observation)).resolves.toEqual({
      registration,
      coin,
      currency: coin.coinShortcut.toLowerCase(),
      observedBackendChain: 'Main_Fixture',
      assertCurrent: expect.any(Function),
    });
    readJson.mockClear();
    await expect(
      observeFirstUseUtxoRpc(url, { ...observation, registration: other })
    ).rejects.toThrow(mismatch);
    expect(readJson.mock.calls).toEqual([[statusUrl, observation.signal]]);
  }
);

it('requires the exact optional tuple and rejects a contradictory modern name', async () => {
  const { observation, readJson } = firstUse(modern);
  await expect(
    observeFirstUseUtxoRpc(url, {
      ...observation,
      registration: { chainId: SYS_TEST.chainId, slip44: 57 },
    })
  ).rejects.toThrow(invalid);
  expect(readJson).not.toHaveBeenCalled();

  readJson.mockResolvedValueOnce({
    blockbook: { network: 'tSYS', coin: 'Bitcoin' },
    backend: { chain: 'test' },
  });
  await expect(observeFirstUseUtxoRpc(url, observation)).rejects.toThrow(
    mismatch
  );
  expect(readJson).toHaveBeenCalledTimes(1);

  await expect(
    observeFirstUseUtxoRpc(url, { ...observation, registration: SYS_TEST })
  ).resolves.toMatchObject({ registration: SYS_TEST });
});

it('rejects an ambiguous legacy alias and genesis even with a selected tuple', async () => {
  const coin = findUtxoCoinByRegistration(SYS_TEST)!;
  coins.push({
    ...coin,
    chainId: 12345,
    coinShortcut: 'OTHER',
    shortcut: 'OTHER',
    name: 'Other',
  });
  const { observation, readJson } = firstUse(legacy);
  await expect(observeFirstUseUtxoRpc(url, observation)).rejects.toThrow(
    mismatch
  );
  await expect(
    observeFirstUseUtxoRpc(url, { ...observation, registration: SYS_TEST })
  ).rejects.toThrow(mismatch);
  expect(readJson).toHaveBeenCalledTimes(4);
});

it('rejects discovered coins with duplicate exact tuples or ambiguous custody tickers', async () => {
  const coin = findUtxoCoinByRegistration(SYS_TEST)!;
  const { observation, readJson } = firstUse(modern);
  coins.push({
    ...coin,
    coinShortcut: 'OTHER',
    shortcut: 'OTHER',
    coinName: 'Other',
    coinLabel: 'Other',
    name: 'Other',
  });
  await expect(observeFirstUseUtxoRpc(url, observation)).rejects.toThrow(
    invalid
  );
  coins.pop();
  coins.push({
    ...coin,
    chainId: 12345,
    coinShortcut: 'OTHER',
    shortcut: 'OTHER',
    coinName: 'tSYS',
    name: 'Other',
  });
  await expect(observeFirstUseUtxoRpc(url, observation)).rejects.toThrow(
    invalid
  );
  expect(readJson).toHaveBeenCalledTimes(4);
});

it('first use requires HTTPS and a bounded primitive reported token', async () => {
  const { observation, readJson } = firstUse(modern);
  for (const endpoint of [
    url.replace('https:', 'http:'),
    'https://username:secret@blockbook.invalid/',
    'https://blockbook.invalid/#fragment',
  ]) {
    await expect(observeFirstUseUtxoRpc(endpoint, observation)).rejects.toThrow(
      invalid
    );
  }
  expect(readJson).not.toHaveBeenCalled();
  for (const chain of [undefined, 1, '', 'test\n', 'test ', 'x'.repeat(33)]) {
    readJson.mockResolvedValueOnce({ ...modern, backend: { chain } });
    await expect(observeFirstUseUtxoRpc(url, observation)).rejects.toThrow(
      invalid
    );
  }
  expect(readJson.mock.calls.every(([route]) => route === statusUrl)).toBe(
    true
  );
});

it.each(['?token=synthetic', '?'])(
  'refuses a Blockbook base query before observation or verification: %s',
  async (query) => {
    const endpoint = `https://blockbook.invalid/tenant/${query}`;
    const { observation, readJson: firstRead } = firstUse(modern);
    const { owner, readJson: verifyRead } = verification(modern);
    for (const read of [firstRead, verifyRead])
      read
        .mockResolvedValueOnce(modern)
        .mockResolvedValueOnce(genesis(SYS_TEST));
    await expect(observeFirstUseUtxoRpc(endpoint, observation)).rejects.toThrow(
      invalid
    );
    await expect(getSysRpc({ url: endpoint }, owner)).rejects.toThrow(invalid);
    expect(firstRead).not.toHaveBeenCalled();
    expect(verifyRead).not.toHaveBeenCalled();
  }
);

it('refuses wrong genesis, and decimals cannot rescue or change a canonical match', async () => {
  const wrong = firstUse(modern, genesis(BTC));
  await expect(observeFirstUseUtxoRpc(url, wrong.observation)).rejects.toThrow(
    mismatch
  );
  const decimals = firstUse({
    ...modern,
    blockbook: { ...modern.blockbook, decimals: 18 },
  });
  await expect(
    observeFirstUseUtxoRpc(url, decimals.observation)
  ).rejects.toThrow(mismatch);
  expect(wrong.readJson).toHaveBeenCalledTimes(2);
  expect(decimals.readJson).toHaveBeenCalledTimes(2);
});

it('rejects revoked first-use scope and never falls back after a refused owned read', async () => {
  const before = firstUse(modern);
  before.controller.abort();
  await expect(observeFirstUseUtxoRpc(url, before.observation)).rejects.toThrow(
    cancelled
  );
  expect(before.readJson).not.toHaveBeenCalled();

  const status = firstUse(modern);
  status.readJson.mockImplementationOnce(async () => {
    status.controller.abort();
    return modern;
  });
  await expect(observeFirstUseUtxoRpc(url, status.observation)).rejects.toThrow(
    cancelled
  );
  expect(status.readJson).toHaveBeenCalledTimes(1);

  const revoked = firstUse(modern);
  let current = true;
  revoked.readJson
    .mockResolvedValueOnce(modern)
    .mockImplementationOnce(async () => {
      current = false;
      return genesis(SYS_TEST);
    });
  await expect(
    observeFirstUseUtxoRpc(url, {
      ...revoked.observation,
      assertCurrent() {
        if (!current) throw new Error('draft replaced');
      },
    })
  ).rejects.toThrow(cancelled);
  expect(revoked.readJson).toHaveBeenCalledTimes(2);

  const refused = firstUse(modern);
  refused.readJson.mockRejectedValueOnce(new Error('redirect refused'));
  await expect(
    observeFirstUseUtxoRpc(url, refused.observation)
  ).rejects.toThrow(/^UTXO registration read failed$/);
  expect(refused.readJson).toHaveBeenCalledTimes(1);
});

it('does not let first use turn a conflicting trusted token into a match', async () => {
  const endpoint = url.replace('https:', 'http:');
  const { owner, readJson } = verification(modern);
  readJson
    .mockResolvedValueOnce(modern)
    .mockResolvedValueOnce(genesis(SYS_TEST));
  await expect(getSysRpc({ url: endpoint }, owner)).resolves.toMatchObject({
    chain: 'test',
  });
  readJson.mockClear();
  await expect(
    getSysRpc({ url }, { ...owner, backendChain: 'main' })
  ).rejects.toThrow(mismatch);
  expect(readJson).toHaveBeenCalledTimes(1);
});

it('captures a chosen first-use identity and owned transport before the status await', async () => {
  const { observation, readJson } = firstUse(modern);
  const owner = { ...observation, registration: { ...SYS_TEST } };
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
  const pending = observeFirstUseUtxoRpc(url, owner);
  await entered;
  Object.assign(owner.registration, BTC);
  owner.readJson = wrongRead;
  release();
  await expect(pending).resolves.toEqual({
    registration: SYS_TEST,
    coin: findUtxoCoinByRegistration(SYS_TEST),
    currency: 'tsys',
    observedBackendChain: 'test',
    assertCurrent: expect.any(Function),
  });
  expect(wrongRead).not.toHaveBeenCalled();
  expect(readJson.mock.calls).toEqual([
    [statusUrl, observation.signal],
    [genesisUrl, observation.signal],
  ]);
});

it.each([
  'chosen tuple collision',
  'automatic custody ticker collision',
  'legacy alias shares genesis',
  'decimals change without provider decimals',
] as const)(
  'refuses catalogue drift while genesis is held: %s',
  async (change) => {
    const coin = findUtxoCoinByRegistration(SYS_TEST)!;
    const originalDecimals = coin.decimals;
    const status =
      change === 'legacy alias shares genesis'
        ? legacy
        : {
            ...modern,
            blockbook: {
              coin: modern.blockbook.coin,
              network: modern.blockbook.network,
            },
          };
    const block = genesis(SYS_TEST);
    const { observation, readJson } = firstUse(status, block);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      readJson
        .mockResolvedValueOnce(status)
        .mockImplementationOnce(async () => {
          resolve();
          await held;
          return block;
        });
    });
    const owner =
      change === 'chosen tuple collision'
        ? { ...observation, registration: SYS_TEST }
        : observation;
    const pending = observeFirstUseUtxoRpc(url, owner);
    await entered;
    const competitor = {
      ...coin,
      name: 'Other',
      coinName: 'Other',
      coinLabel: 'Other',
      coinShortcut: 'OTHER',
      shortcut: 'OTHER',
    };
    if (change === 'chosen tuple collision') coins.push(competitor);
    else if (change === 'automatic custody ticker collision') {
      coins.unshift({ ...competitor, chainId: 12345, coinName: 'tSYS' });
    } else if (change === 'legacy alias shares genesis') {
      coins.push({
        ...competitor,
        chainId: 12345,
        slip44: 12345,
        coinName: 'Syscoin',
      });
    } else coin.decimals = 18;
    release();
    try {
      await expect(pending).rejects.toThrow(
        /Invalid UTXO registration|does not match/
      );
      expect(readJson.mock.calls).toEqual([
        [statusUrl, owner.signal],
        [genesisUrl, owner.signal],
      ]);
    } finally {
      coin.decimals = originalDecimals;
    }
  }
);

it('checks the live catalogue after the final synchronous owner guard', async () => {
  const coin = findUtxoCoinByRegistration(SYS_TEST)!;
  const { observation, readJson } = firstUse(modern);
  let checks = 0;
  await expect(
    observeFirstUseUtxoRpc(url, {
      ...observation,
      registration: SYS_TEST,
      assertCurrent() {
        if (++checks === 5) coins.push({ ...coin });
      },
    })
  ).rejects.toThrow(invalid);
  expect(readJson).toHaveBeenCalledTimes(2);
});

it.each([legacy, modern])(
  'preserves the selected testnet identity through the existing custody lookup',
  async (status) => {
    const { owner, readJson } = verification(status);
    const result = await getSysRpc(
      {
        url,
        label: 'Custom name',
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

it.each(['alias collision', 'changed address encoding'] as const)(
  'refuses pinned catalogue drift while genesis is held: %s',
  async (change) => {
    const coin = findUtxoCoinByRegistration(SYS_TEST)!;
    const previousPrefix = coin.bech32Prefix;
    const block = genesis(SYS_TEST);
    const { owner, readJson } = verification(modern, block);
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    const entered = new Promise<void>((resolve) => {
      readJson
        .mockResolvedValueOnce(modern)
        .mockImplementationOnce(async () => {
          resolve();
          await held;
          return block;
        });
    });
    const pending = getSysRpc({ url }, owner);
    await entered;
    if (change === 'alias collision')
      coins.unshift({ ...coin, chainId: 12345, coinName: 'TSYS' });
    else coin.bech32Prefix = 'wrong';
    release();
    try {
      await expect(pending).rejects.toThrow(
        change === 'alias collision' ? mismatch : invalid
      );
      expect(readJson).toHaveBeenCalledTimes(2);
    } finally {
      coin.bech32Prefix = previousPrefix;
    }
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
  await expect(
    Reflect.apply(getSysRpc, undefined, [{ url, label: {} }, owner])
  ).rejects.toThrow('Invalid UTXO registration draft');
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

it('never uses ambient fetch or echoes an owned transport failure', async () => {
  const { owner, readJson } = verification(modern);
  readJson.mockRejectedValueOnce(new Error('private fixture diagnostic'));
  await expect(getSysRpc({ url }, owner)).rejects.toThrow(
    /^UTXO registration read failed$/
  );
  expect(readJson.mock.calls).toEqual([[statusUrl, owner.signal]]);
  expect(ambient).not.toHaveBeenCalled();
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
