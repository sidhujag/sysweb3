import ecc from '@bitcoinerlab/secp256k1';
import { keccak256 } from 'ethers/crypto';
import { Transaction, recoverAddress } from 'ethers/transaction';
import { HDNodeWallet, Wallet } from 'ethers/wallet';

import { EvmGasLimitError } from '../../../src/evm-fees';
import {
  SoftwareKeyring,
  createKeyringHost,
  INetworkType,
  KeyringAccountType,
} from '../../../src/software';
import {
  serializePreparedEvmTransaction,
  snapshotEvmAccessList,
} from '../../../src/transactions/evm-envelope';
import { snapshotPreparedEvmRequest } from '../../../src/transactions/prepared-evm';

import type { PreparedSoftwareEvmSigningRequest } from '../../../src/software';

const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PASSWORD = 'public prepared transaction fixture';
const ADDRESS = '0x9858EfFD232B4033E47d90003D41EC34EcaEda94';
const RECIPIENT = '0x1111111111111111111111111111111111111111';
const URL = 'https://offline.invalid';
const referenceWallet = HDNodeWallet.fromPhrase(
  PHRASE,
  undefined,
  "m/44'/60'/0'/0/0"
);

function request(type: 0 | 2 = 2): PreparedSoftwareEvmSigningRequest {
  return {
    selectedAccount: { id: 0, type: 'HDAccount', expectedAddress: ADDRESS },
    account: { id: 0, type: 'HDAccount', expectedAddress: ADDRESS },
    network: { kind: 'ethereum', chainId: '1', slip44: 60, url: URL },
    transaction: {
      type,
      from: ADDRESS,
      to: RECIPIENT,
      chainId: '1',
      nonce: '7',
      value: '1000000000000000000',
      gasLimit: '21000',
      data: '0x',
      ...(type === 0
        ? { gasPrice: '20000000000' }
        : {
            maxFeePerGas: '30000000000',
            maxPriorityFeePerGas: '1000000000',
            accessList: [],
          }),
    } as any,
  };
}

function fixtureState() {
  return {
    activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
    activeNetwork: {
      kind: INetworkType.Ethereum,
      chainId: 1,
      slip44: 60,
      label: 'Ethereum',
      currency: 'ETH',
      url: URL,
    },
    accounts: {
      HDAccount: {},
      Imported: {},
      Ledger: {},
      Trezor: {},
      SmartAccount: {},
    },
  } as any;
}

const mutations: Array<[string, (input: any) => void]> = [
  ['missing nonce', (v) => delete v.transaction.nonce],
  ['numeric nonce', (v) => (v.transaction.nonce = 7)],
  ['negative nonce', (v) => (v.transaction.nonce = '-1')],
  ['fractional nonce', (v) => (v.transaction.nonce = '0.5')],
  ['unsafe nonce', (v) => (v.transaction.nonce = '9007199254740992')],
  ['noncanonical decimal', (v) => (v.transaction.value = '01')],
  ['hexadecimal value', (v) => (v.transaction.value = '0x10')],
  ['oversized value', (v) => (v.transaction.value = (1n << 256n).toString())],
  [
    'fee plus value overflow',
    (v) => (v.transaction.value = ((1n << 256n) - 1n).toString()),
  ],
  ['missing gas', (v) => delete v.transaction.gasLimit],
  ['zero gas', (v) => (v.transaction.gasLimit = '0')],
  ['oversized gas', (v) => (v.transaction.gasLimit = (1n << 64n).toString())],
  ['missing fee', (v) => delete v.transaction.maxFeePerGas],
  [
    'priority above maximum',
    (v) => (v.transaction.maxPriorityFeePerGas = '30000000001'),
  ],
  ['mixed fees', (v) => (v.transaction.gasPrice = '1')],
  ['unsupported type', (v) => (v.transaction.type = 4)],
  ['string type', (v) => (v.transaction.type = '2')],
  ['missing type', (v) => delete v.transaction.type],
  ['unknown transaction field', (v) => (v.transaction.unexpected = [])],
  ['missing access list', (v) => delete v.transaction.accessList],
  ['invalid access list', (v) => (v.transaction.accessList = {})],
  ['unknown root field', (v) => (v.extra = true)],
  ['ENS recipient', (v) => (v.transaction.to = 'alice.eth')],
  ['missing recipient', (v) => delete v.transaction.to],
  [
    'zero sender',
    (v) => {
      v.transaction.from = '0x' + '0'.repeat(40);
      v.account.expectedAddress = v.transaction.from;
    },
  ],
  [
    'invalid checksum',
    (v) => (v.transaction.from = '0x9858EFFD232B4033E47d90003D41EC34EcaEda94'),
  ],
  ['wrong sender', (v) => (v.transaction.from = RECIPIENT)],
  ['mismatched chain', (v) => (v.transaction.chainId = '2')],
  [
    'zero chain',
    (v) => {
      v.transaction.chainId = '0';
      v.network.chainId = '0';
    },
  ],
  ['unknown network field', (v) => (v.network.privateKey = 'not permitted')],
  ['wrong network family', (v) => (v.network.kind = 'syscoin')],
  ['wrong slip44', (v) => (v.network.slip44 = 57)],
  ['blank endpoint', (v) => (v.network.url = '')],
  ['control in endpoint', (v) => (v.network.url += String.fromCharCode(0))],
  ['oversized endpoint', (v) => (v.network.url = 'x'.repeat(4097))],
  ['negative account id', (v) => (v.account.id = -1)],
  ['hardware account type', (v) => (v.account.type = 'Ledger')],
  ['odd hex data', (v) => (v.transaction.data = '0x1')],
  ['non-hex data', (v) => (v.transaction.data = '0xgg')],
  ['unprefixed data', (v) => (v.transaction.data = 'abcd')],
  [
    'oversized data',
    (v) => (v.transaction.data = '0x' + 'ab'.repeat(512 * 1024 + 1)),
  ],
];

it.each(mutations)('rejects %s before signing', (_name, mutate) => {
  const input = request();
  mutate(input);
  expect(() => snapshotPreparedEvmRequest(input)).toThrow();
});

it.each([
  ['1', '16777216', '16777217'],
  ['11155111', '4294967295', '4294967296'],
  ['560048', '16777216', '16777217'],
])(
  'bounds prepared gas for activated chain %s',
  (chainId, limit, aboveLimit) => {
    const input = request() as any;
    input.network.chainId = input.transaction.chainId = chainId;
    input.transaction.gasLimit = limit;
    expect(snapshotPreparedEvmRequest(input).transaction.gasLimit).toBe(limit);
    input.transaction.gasLimit = aboveLimit;
    expect(() => snapshotPreparedEvmRequest(input)).toThrow(EvmGasLimitError);
  }
);

it('accepts prepared Sepolia total gas above its separate execution-gas cap', () => {
  const input = request() as any;
  input.network.chainId = input.transaction.chainId = '11155111';
  input.transaction.gasLimit = '16800000';
  expect(snapshotPreparedEvmRequest(input).transaction.gasLimit).toBe(
    '16800000'
  );
});

it('does not infer an Ethereum gas cap on unrelated prepared EVM chains', () => {
  const input = request() as any;
  input.network.chainId = input.transaction.chainId = '5700';
  input.transaction.gasLimit = '16800000';
  expect(snapshotPreparedEvmRequest(input).transaction.gasLimit).toBe(
    '16800000'
  );
});

it('rejects accessors, prototypes, symbols and nonenumerable fields without invoking getters', () => {
  const accessor = request();
  const getter = jest.fn();
  Object.defineProperty(accessor.transaction, 'nonce', {
    get: getter,
    enumerable: true,
  });
  expect(() => snapshotPreparedEvmRequest(accessor)).toThrow();
  expect(getter).not.toHaveBeenCalled();
  const symbol = request() as any;
  symbol[Symbol('hidden')] = true;
  expect(() => snapshotPreparedEvmRequest(symbol)).toThrow();
  const hidden = request();
  Object.defineProperty(hidden.transaction, 'nonce', {
    value: '7',
    enumerable: false,
  });
  expect(() => snapshotPreparedEvmRequest(hidden)).toThrow();
  const prototype = request();
  Object.setPrototypeOf(prototype.transaction, { extra: true });
  expect(() => snapshotPreparedEvmRequest(prototype)).toThrow();
});

it('normalizes and detaches the complete admitted request at the maximum calldata size', () => {
  const input = request() as any;
  input.account.expectedAddress = ADDRESS.toLowerCase();
  input.transaction.from = ADDRESS.toLowerCase();
  input.transaction.data = '0x' + 'AB'.repeat(512 * 1024);
  const copy = snapshotPreparedEvmRequest(input);
  input.transaction.nonce = '8';
  input.account.id = 1;
  expect(copy.transaction.nonce).toBe('7');
  expect(copy.account.id).toBe(0);
  expect(copy.transaction.from).toBe(ADDRESS);
  expect(copy.transaction.data).toBe('0x' + 'ab'.repeat(512 * 1024));
  expect(Object.isFrozen(copy)).toBe(true);
  expect(Object.isFrozen(copy.transaction)).toBe(true);
  expect(Object.isFrozen(copy.account)).toBe(true);
  expect(Object.isFrozen(copy.network)).toBe(true);
});

it('requires access lists only on type-2 envelopes', () => {
  const legacy = request(0) as any;
  legacy.transaction.accessList = [];
  expect(() => snapshotPreparedEvmRequest(legacy)).toThrow();
  const typed = request(2) as any;
  delete typed.transaction.accessList;
  expect(() => snapshotPreparedEvmRequest(typed)).toThrow();
  expect(() => serializePreparedEvmTransaction(typed.transaction)).toThrow();
});

it('uses the same canonical unsigned fields for contract creation and access-list calls', () => {
  const input = request(2) as any;
  input.transaction.to = null;
  input.transaction.data = '0x6080';
  input.transaction.accessList = [
    { address: RECIPIENT, storageKeys: ['0x' + '11'.repeat(32)] },
  ];
  const serialized = serializePreparedEvmTransaction(input.transaction);
  const decoded = Transaction.from(serialized);
  expect(decoded.to).toBeNull();
  expect(decoded.data).toBe(input.transaction.data);
  expect(decoded.accessList).toEqual(input.transaction.accessList);
  expect(decoded.isSigned()).toBe(false);
  expect(serialized).toBe(
    Transaction.from({ ...input.transaction, from: undefined, nonce: 7 })
      .unsignedSerialized
  );
});

it('copies access-list order and duplicates and freezes every nested value', () => {
  const key = '0x' + 'AB'.repeat(32);
  const entry = { address: ADDRESS.toLowerCase(), storageKeys: [key, key] };
  const input = [entry, entry];
  const copy = snapshotEvmAccessList(input);
  entry.address = RECIPIENT;
  entry.storageKeys[0] = '0x' + '00'.repeat(32);
  input.pop();
  expect(copy).toEqual([
    { address: ADDRESS, storageKeys: [key.toLowerCase(), key.toLowerCase()] },
    { address: ADDRESS, storageKeys: [key.toLowerCase(), key.toLowerCase()] },
  ]);
  expect(Object.isFrozen(copy)).toBe(true);
  expect(copy.every((item) => Object.isFrozen(item))).toBe(true);
  expect(copy.every((item) => Object.isFrozen(item.storageKeys))).toBe(true);
});

it('rejects malformed, sparse or accessor access lists without invoking getters', () => {
  const getter = jest.fn();
  const entry = { address: RECIPIENT, storageKeys: [] };
  Object.defineProperty(entry, 'address', { get: getter, enumerable: true });
  const indexed = [RECIPIENT];
  Object.defineProperty(indexed, 0, { get: getter, enumerable: true });
  for (const input of [
    undefined,
    {},
    [entry],
    new Array(1),
    [{ address: RECIPIENT, storageKeys: indexed }],
    [{ address: RECIPIENT, storageKeys: ['0x1'] }],
    [{ address: RECIPIENT, storageKeys: [], extra: true }],
  ])
    expect(() => snapshotEvmAccessList(input)).toThrow();
  expect(getter).not.toHaveBeenCalled();
});

it('bounds total copied access-list entries and storage keys', () => {
  const key = '0x' + 'ab'.repeat(32);
  expect(
    snapshotEvmAccessList([
      { address: RECIPIENT, storageKeys: Array(9_999).fill(key) },
    ])[0].storageKeys
  ).toHaveLength(9_999);
  expect(() =>
    snapshotEvmAccessList([
      { address: RECIPIENT, storageKeys: Array(10_000).fill(key) },
    ])
  ).toThrow();
});

describe('software-only prepared signing authority', () => {
  let keyring: SoftwareKeyring;
  let state: any;
  let sign: jest.SpyInstance;
  let provider: jest.SpyInstance;
  let fetch: jest.SpyInstance;
  let guard: jest.Mock;
  beforeEach(async () => {
    const values = new Map<string, any>();
    const storage = {
      async get(key: string) {
        return values.get(key);
      },
      async set(key: string, value: unknown) {
        values.set(key, value);
      },
      async deleteItem(key: string) {
        values.delete(key);
      },
      async createManyIfAbsent(items: Record<string, unknown>) {
        if (Object.keys(items).some((key) => values.has(key))) return false;
        Object.entries(items).forEach(([key, value]) => values.set(key, value));
        return true;
      },
    };
    state = fixtureState();
    keyring = new SoftwareKeyring(createKeyringHost(storage), {
      captureEvmSubmission: null,
    });
    keyring.setVaultStateGetter(() => state);
    state.accounts.HDAccount[0] = await keyring.initializeWalletSecurely(
      PHRASE,
      PASSWORD
    );
    expect(state.accounts.HDAccount[0].address).toBe(ADDRESS);
    sign = jest.spyOn(ecc, 'signRecoverable');
    provider = jest
      .spyOn(keyring.ethereumTransaction, 'web3Provider', 'get')
      .mockImplementation(() => {
        throw new Error('No provider access allowed');
      });
    fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockRejectedValue(new Error('No network allowed'));
    guard = jest.fn();
  });
  afterEach(async () => {
    await keyring.destroy();
    jest.restoreAllMocks();
  });

  it.each([0, 2] as const)(
    'signs a complete type %i envelope matching the independent wallet',
    async (type) => {
      const input = request(type);
      const result = keyring.signPreparedEvmTransaction(input, {
        assertCurrent: guard,
      });
      const reference = await referenceWallet.signTransaction({
        ...input.transaction,
        nonce: 7,
        ...(input.transaction.type === 2
          ? {
              accessList: input.transaction.accessList.map((item) => ({
                address: item.address,
                storageKeys: [...item.storageKeys],
              })),
            }
          : {}),
      });
      expect(result.rawTransaction).toBe(reference);
      const decoded = Transaction.from(result.rawTransaction);
      expect(decoded.from).toBe(ADDRESS);
      expect(decoded.to).toBe(RECIPIENT);
      expect(decoded.value.toString()).toBe(input.transaction.value);
      expect(result.hash).toBe(keccak256(reference));
      expect(result.unsignedHash).toBe(decoded.unsignedHash);
      expect(result.transaction).toEqual(input.transaction);
      expect(Object.isFrozen(result)).toBe(true);
      expect(sign).toHaveBeenCalledTimes(1);
      expect(provider).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
      expect(guard).toHaveBeenCalledTimes(2);
    }
  );

  it.each([0, 2] as const)(
    'signs a type-%i contract creation with its exact initcode',
    async (type) => {
      const input = request(type) as any;
      input.transaction.to = null;
      input.transaction.data = '0x' + '60'.repeat(32 * 1024);
      input.transaction.gasLimit = '2000000';
      const result = keyring.signPreparedEvmTransaction(input, {
        assertCurrent: guard,
      });
      const reference = await referenceWallet.signTransaction({
        ...input.transaction,
        nonce: 7,
      });
      expect(result.rawTransaction).toBe(reference);
      const decoded = Transaction.from(result.rawTransaction);
      expect(decoded.to).toBeNull();
      expect(decoded.data).toBe(input.transaction.data);
      expect(provider).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    }
  );

  it('signs an explicit zero destination while refusing a zero sender', () => {
    const input = request() as any;
    input.transaction.to = '0x' + '0'.repeat(40);
    const signed = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    expect(Transaction.from(signed.rawTransaction).to).toBe(
      input.transaction.to
    );
    input.account.expectedAddress = input.transaction.from =
      input.transaction.to;
    expect(() =>
      keyring.signPreparedEvmTransaction(input, { assertCurrent: guard })
    ).toThrow();
    expect(sign).toHaveBeenCalledTimes(1);
  });

  it('signs the captured ordered access list even when a host callback mutates it', async () => {
    const input = request(2) as any;
    const entry = {
      address: RECIPIENT,
      storageKeys: ['0x' + '11'.repeat(32), '0x' + '11'.repeat(32)],
    };
    input.transaction.accessList = [entry, entry];
    const expected = structuredClone(input.transaction);
    guard.mockImplementation(() => {
      entry.address = ADDRESS;
      entry.storageKeys[0] = '0x' + '22'.repeat(32);
      input.transaction.accessList.pop();
    });
    const result = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    const reference = await referenceWallet.signTransaction({
      ...expected,
      nonce: 7,
    });
    expect(result.rawTransaction).toBe(reference);
    expect(Transaction.from(result.rawTransaction).accessList).toEqual(
      expected.accessList
    );
    expect(result.transaction).toEqual(expected);
    expect(provider).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each([0, 2] as const)(
    'refuses to sign an over-cap type %i envelope even without estimation',
    (type) => {
      const input = request(type) as any;
      input.transaction.gasLimit = '16777217';
      expect(() =>
        keyring.signPreparedEvmTransaction(input, { assertCurrent: guard })
      ).toThrow(EvmGasLimitError);
      expect(sign).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();
      expect(fetch).not.toHaveBeenCalled();
    }
  );

  it('accepts a historically lowercase stored public address and returns checksummed identity', () => {
    state.accounts.HDAccount[0].address = ADDRESS.toLowerCase();
    const input = request() as any;
    input.account.expectedAddress = ADDRESS.toLowerCase();
    input.transaction.from = ADDRESS.toLowerCase();
    const result = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    expect(result.from).toBe(ADDRESS);
    expect(result.transaction.from).toBe(ADDRESS);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('refuses replacing the host state getter after its initial binding', () => {
    const replacement = jest.fn(() => state);
    expect(() => keyring.setVaultStateGetter(replacement)).toThrow(
      'already bound'
    );
    expect(replacement).not.toHaveBeenCalled();
    expect(
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
        .from
    ).toBe(ADDRESS);
  });

  function selectSmartAccount() {
    state.accounts.SmartAccount[7] = {
      id: 7,
      address: RECIPIENT,
      isSmartAccount: true,
      xprv: '',
    };
    state.activeAccount = { id: 7, type: KeyringAccountType.SmartAccount };
    return { id: 7, type: 'SmartAccount' as const, expectedAddress: RECIPIENT };
  }

  it('signs for the explicit software payer while preserving selected smart-account identity', () => {
    const selectedAccount = selectSmartAccount();
    const input = { ...request(), selectedAccount };
    const signed = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    expect(signed.from).toBe(ADDRESS);
    expect(state.activeAccount).toEqual({
      id: 7,
      type: KeyringAccountType.SmartAccount,
    });
    expect(provider).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['selected', 'payer', 'key'])(
    'rejects changes to the %s binding before an explicit-target signature',
    (field) => {
      const selectedAccount = selectSmartAccount();
      guard.mockImplementationOnce(() => {
        if (field === 'selected')
          state.accounts.SmartAccount[7].address = ADDRESS;
        if (field === 'payer') state.accounts.HDAccount[0].address = RECIPIENT;
        if (field === 'key') state.accounts.HDAccount[0].xprv = 'changed';
      });
      expect(() =>
        keyring.signPreparedEvmTransaction(
          { ...request(), selectedAccount },
          { assertCurrent: guard }
        )
      ).toThrow();
      expect(sign).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();
    }
  );

  it('signs the same raw digest for the explicit owner without selecting it', async () => {
    const selectedAccount = selectSmartAccount();
    const digest = '0x' + '12'.repeat(32);
    const signature = await keyring.ethereumTransaction.ethSign(
      [ADDRESS, digest],
      {
        signal: new AbortController().signal,
        selectedAccount,
        targetAccount: request().account,
        assertCurrent: guard,
      }
    );
    expect(recoverAddress(digest, signature)).toBe(ADDRESS);
    expect(state.activeAccount.type).toBe(KeyringAccountType.SmartAccount);
    expect(provider).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rechecks the selected account after a synchronous digest guard revokes it', async () => {
    const selectedAccount = selectSmartAccount();
    guard.mockImplementationOnce(() => {
      state.activeAccount = { id: 0, type: KeyringAccountType.HDAccount };
    });
    await expect(
      keyring.ethereumTransaction.ethSign([ADDRESS, '0x' + '12'.repeat(32)], {
        signal: new AbortController().signal,
        selectedAccount,
        targetAccount: request().account,
        assertCurrent: guard,
      })
    ).rejects.toThrow();
    expect(sign).not.toHaveBeenCalled();
    expect(provider).not.toHaveBeenCalled();
  });

  it('snapshots the approved digest before invoking the host guard', async () => {
    const selectedAccount = selectSmartAccount();
    const digest = '0x' + '12'.repeat(32);
    const params = [ADDRESS, digest];
    guard.mockImplementationOnce(() => {
      params[1] = '0x' + '34'.repeat(32);
    });
    const signature = await keyring.ethereumTransaction.ethSign(params, {
      signal: new AbortController().signal,
      selectedAccount,
      targetAccount: request().account,
      assertCurrent: guard,
    });
    expect(recoverAddress(digest, signature)).toBe(ADDRESS);
  });

  it('rejects missing or asynchronous digest authority before signing', async () => {
    const selectedAccount = selectSmartAccount();
    const digest = '0x' + '12'.repeat(32);
    await expect(
      keyring.ethereumTransaction.ethSign([ADDRESS, digest], undefined as never)
    ).rejects.toThrow();
    await expect(
      keyring.ethereumTransaction.ethSign([ADDRESS, digest], {
        signal: new AbortController().signal,
        selectedAccount,
        targetAccount: request().account,
        assertCurrent: async () => undefined,
      })
    ).rejects.toThrow();
    expect(sign).not.toHaveBeenCalled();
  });

  it('signs an imported software account without exposing its key', async () => {
    const wallet = new Wallet(
      '0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    );
    const account = await keyring.importAccount(wallet.privateKey);
    state.accounts.Imported[account.id] = account;
    state.activeAccount = { type: KeyringAccountType.Imported, id: account.id };
    const input = request() as any;
    input.account = {
      id: account.id,
      type: 'Imported',
      expectedAddress: account.address,
    };
    input.transaction.from = account.address;
    input.selectedAccount = { ...input.account };
    const result = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    expect(result.from).toBe(wallet.address);
    expect(JSON.stringify(result)).not.toContain(wallet.privateKey.slice(2));
    expect(fetch).not.toHaveBeenCalled();
  });

  it('freezes the requested transaction before a host callback can replace its values or guard', () => {
    const input = request() as any;
    const options = { assertCurrent: guard };
    guard.mockImplementation(() => {
      input.transaction.to = ADDRESS;
      input.transaction.value = '2';
      options.assertCurrent = jest.fn();
    });
    const result = keyring.signPreparedEvmTransaction(input, options);
    expect(Transaction.from(result.rawTransaction).to).toBe(RECIPIENT);
    expect(Transaction.from(result.rawTransaction).value.toString()).toBe(
      '1000000000000000000'
    );
    expect(guard).toHaveBeenCalledTimes(2);
    expect(options.assertCurrent).not.toHaveBeenCalled();
  });

  it.each(['lock', 'reset', 'network', 'endpoint', 'account', 'key'])(
    'rejects a reentrant %s before accessing a signing key',
    (change) => {
      guard.mockImplementationOnce(() => {
        if (change === 'lock') void keyring.lockWallet();
        if (change === 'reset') keyring.logout();
        if (change === 'network') state.activeNetwork.chainId = 2;
        if (change === 'endpoint')
          state.activeNetwork.url = 'https://other.invalid';
        if (change === 'account') state.activeAccount.id = 1;
        if (change === 'key') state.accounts.HDAccount[0].xprv = 'different';
      });
      expect(() =>
        keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
      ).toThrow();
      expect(sign).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();
    }
  );

  it('withholds the signed result if lock occurs during signing', () => {
    const original = sign.getMockImplementation()!;
    sign.mockImplementationOnce((...args) => {
      const value = original(...args);
      void keyring.lockWallet();
      return value;
    });
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
    ).toThrow();
    expect(sign).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(['network', 'account'])(
    'withholds the signed result if %s changes while signing',
    (change) => {
      const original = sign.getMockImplementation()!;
      sign.mockImplementationOnce((...args) => {
        const signature = original(...args);
        if (change === 'network') state.activeNetwork.chainId = 2;
        else state.activeAccount.id = 1;
        return signature;
      });
      expect(() =>
        keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
      ).toThrow();
      expect(sign).toHaveBeenCalledTimes(1);
      expect(fetch).not.toHaveBeenCalled();
    }
  );

  it('withholds a result when the final guard becomes asynchronous', async () => {
    guard
      .mockImplementationOnce(() => undefined)
      .mockImplementationOnce(() => Promise.reject(new Error('Expired')));
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
    ).toThrow('synchronously');
    await Promise.resolve();
    await Promise.resolve();
    expect(sign).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('withholds the result if its final host admission fails', () => {
    guard
      .mockImplementationOnce(() => undefined)
      .mockImplementationOnce(() => {
        throw new Error('Review expired');
      });
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
    ).toThrow('Review expired');
    expect(sign).toHaveBeenCalledTimes(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects the wrong expected address, endpoint, chain or account', () => {
    const wrongAddress = request() as any;
    wrongAddress.account.expectedAddress = RECIPIENT;
    wrongAddress.transaction.from = RECIPIENT;
    const wrongEndpoint = request() as any;
    wrongEndpoint.network.url = 'https://other.invalid';
    const wrongChain = request() as any;
    wrongChain.network.chainId = wrongChain.transaction.chainId = '2';
    const wrongAccount = request() as any;
    wrongAccount.account.id = 1;
    for (const input of [wrongAddress, wrongEndpoint, wrongChain, wrongAccount])
      expect(() =>
        keyring.signPreparedEvmTransaction(input, { assertCurrent: guard })
      ).toThrow();
    expect(sign).not.toHaveBeenCalled();
    expect(guard).not.toHaveBeenCalled();
  });

  it.each(['isLedgerWallet', 'isTrezorWallet', 'isSmartAccount', 'watch-only'])(
    'rejects %s metadata without provider/device fallback',
    (flag) => {
      if (flag === 'watch-only') state.accounts.HDAccount[0].xprv = '';
      else state.accounts.HDAccount[0][flag] = true;
      expect(() =>
        keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
      ).toThrow();
      expect(sign).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();
    }
  );

  it.each([
    KeyringAccountType.Ledger,
    KeyringAccountType.Trezor,
    KeyringAccountType.SmartAccount,
  ])(
    'rejects a selected %s account despite software-looking request data',
    (type) => {
      state.accounts[type][0] = { ...state.accounts.HDAccount[0] };
      state.activeAccount.type = type;
      expect(() =>
        keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
      ).toThrow();
      expect(sign).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();
    }
  );

  it.each([
    undefined,
    null,
    {},
    [],
    { assertCurrent: false },
    { assertCurrent: () => true },
  ])('requires a synchronous void host guard: %p', (options) => {
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), options as any)
    ).toThrow();
    expect(sign).not.toHaveBeenCalled();
  });

  it('rejects and observes an asynchronous guard rejection', async () => {
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), {
        assertCurrent: (() => Promise.reject(new Error('Denied'))) as any,
      })
    ).toThrow();
    await Promise.resolve();
    await Promise.resolve();
    expect(sign).not.toHaveBeenCalled();
  });

  it('rejects a corrupted signature that recovers another key', () => {
    const other = new Wallet(
      '0x2222222222222222222222222222222222222222222222222222222222222222'
    );
    const original = sign.getMockImplementation()!;
    sign.mockImplementationOnce((digest) =>
      original(digest, Buffer.from(other.privateKey.slice(2), 'hex'))
    );
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
    ).toThrow('does not match');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('rejects valid same-signer bytes for a different transaction', () => {
    const signer = jest.requireActual(
      '../../../src/transactions/evm-local-signer'
    );
    const original = signer.signTransaction;
    jest
      .spyOn(signer, 'signTransaction')
      .mockImplementationOnce((transaction: any, key: string) =>
        original({ ...transaction, value: 2n }, key)
      );
    expect(() =>
      keyring.signPreparedEvmTransaction(request(), { assertCurrent: guard })
    ).toThrow('does not match');
    expect(fetch).not.toHaveBeenCalled();
  });

  it('never returns a key/seed/private record or modifies a caller object', () => {
    const input = request();
    const original = structuredClone(input);
    const result = keyring.signPreparedEvmTransaction(input, {
      assertCurrent: guard,
    });
    expect(input).toEqual(original);
    expect(Object.keys(result).sort()).toEqual([
      'from',
      'hash',
      'rawTransaction',
      'transaction',
      'unsignedHash',
    ]);
    expect(JSON.stringify(result)).not.toContain(PHRASE);
    expect(JSON.stringify(result)).not.toContain(
      referenceWallet.privateKey.slice(2)
    );
  });
});
