import { recoverPersonalSignature } from '@metamask/eth-sig-util';

import {
  SoftwareKeyring,
  createKeyringHost,
  KeyringAccountType,
  INetworkType,
} from '../../../src/software';

import type {
  KeyringStoragePort,
  SecretOperationCredentialPort,
} from '../../../src/software';

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public operation fixture password';
const noop = () => undefined;
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
function fixture(policy: 'session' | 'operation' = 'operation') {
  const records = new Map<string, unknown>();
  const storage: KeyringStoragePort = {
    get: async (key) => records.get(key),
    set: async (key, value) => {
      records.set(key, value);
    },
    deleteItem: async (key) => {
      records.delete(key);
    },
    createManyIfAbsent: async (items) => {
      if (Object.keys(items).some((key) => records.has(key))) return false;
      Object.entries(items).forEach(([key, value]) => records.set(key, value));
      return true;
    },
  };
  const host = createKeyringHost(storage);
  const state: any = {
    activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
    activeNetwork: {
      kind: INetworkType.Ethereum,
      chainId: 1,
      slip44: 60,
      label: 'Ethereum',
      currency: 'ETH',
      url: 'https://offline.invalid',
    },
    accounts: {
      HDAccount: {},
      Imported: {},
      Ledger: {},
      Trezor: {},
      SmartAccount: {},
    },
  };
  const create = () => {
    const keyring = new SoftwareKeyring(host, {
      captureEvmSubmission: null,
      secretLifetime: policy,
    });
    keyring.setVaultStateGetter(() => state);
    return keyring;
  };
  const keyring = create();
  const initialize = async () => {
    state.accounts.HDAccount[0] = await keyring.initializeWalletSecurely(
      mnemonic,
      password
    );
  };
  return { keyring, initialize, create, state };
}
const port: SecretOperationCredentialPort = {
  async withSecret(check, consume) {
    check();
    await consume(password);
    check();
  },
};
const options = (signal = new AbortController().signal) => ({
  signal,
  assertCurrent: noop,
});
const noBuffers = (ring: SoftwareKeyring) => {
  expect((ring as any).sessionPassword).toBeNull();
  expect((ring as any).sessionMnemonic).toBeNull();
  expect(ring.isUnlocked()).toBe(false);
};

it('initializes and unlocks the public session without retaining software secret material', async () => {
  const f = fixture();
  try {
    await f.initialize();
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
    expect(f.keyring.getActiveAccount().activeAccount.address).toBe(
      f.state.accounts.HDAccount[0].address
    );
    await expect(f.keyring.getSeed(password)).rejects.toThrow(
      'Unlock wallet first'
    );
    await expect(
      f.keyring.initializeSession(mnemonic, password)
    ).rejects.toThrow('secret operation');
    const provider = f.keyring.ethereumTransaction,
      utxo = f.keyring.syscoinTransaction;
    const publicGuard = f.keyring.capturePublicSessionGuard();
    const result = await f.keyring.withSecretOperation(
      port,
      options(),
      async () => {
        expect(f.keyring.isUnlocked()).toBe(true);
        expect(await f.keyring.getSeed(password)).toBe(mnemonic);
        return f.keyring.getPrivateRecordProfileId();
      }
    );
    expect(result).toMatch(/^0x[0-9a-f]+$/);
    noBuffers(f.keyring);
    publicGuard();
    expect(f.keyring.ethereumTransaction).toBe(provider);
    expect(f.keyring.syscoinTransaction).toBe(utxo);
    await f.keyring.lockWallet();
    expect(f.keyring.hasPublicSession()).toBe(false);
    expect(() => publicGuard()).toThrow();
    expect(await f.keyring.unlock(password)).toEqual({ canLogin: true });
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
  } finally {
    await f.keyring.destroy();
  }
});

it('preserves the explicit extension session policy', async () => {
  const f = fixture('session');
  try {
    await f.initialize();
    expect(f.keyring.isUnlocked()).toBe(true);
    expect(await f.keyring.getSeed(password)).toBe(mnemonic);
    await expect(
      f.keyring.withSecretOperation(port, options(), noop)
    ).rejects.toThrow('Operation secret policy');
    expect(f.keyring.isUnlocked()).toBe(true);
  } finally {
    await f.keyring.destroy();
  }
});

it('clears software secrets on work failure, and rejects omitted, duplicate and concurrent credential entry', async () => {
  const f = fixture();
  await f.initialize();
  try {
    await expect(
      f.keyring.withSecretOperation(port, options(), () => {
        throw Error('work failed');
      })
    ).rejects.toThrow('work failed');
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
    await expect(
      f.keyring.withSecretOperation(
        {
          async withSecret() {
            return undefined;
          },
        },
        options(),
        noop
      )
    ).rejects.toThrow('not consumed');
    let runs = 0;
    await expect(
      f.keyring.withSecretOperation(
        {
          async withSecret(_check, consume) {
            await consume(password);
            await consume(password);
          },
        },
        options(),
        () => {
          runs++;
        }
      )
    ).rejects.toThrow('already consumed');
    expect(runs).toBe(1);
    noBuffers(f.keyring);
    const held = deferred();
    const started = deferred();
    const first = f.keyring.withSecretOperation(port, options(), async () => {
      started.resolve();
      await held.promise;
    });
    await started.promise;
    await expect(
      f.keyring.withSecretOperation(port, options(), noop)
    ).rejects.toThrow('busy');
    held.resolve();
    await first;
    noBuffers(f.keyring);
  } finally {
    await f.keyring.destroy();
  }
});

it('cancellation clears immediately and retires captured secret guards while keeping the public context', async () => {
  const f = fixture();
  await f.initialize();
  const held = deferred(),
    started = deferred();
  const abort = new AbortController();
  let guard!: () => void;
  try {
    const pending = f.keyring.withSecretOperation(
      port,
      options(abort.signal),
      async () => {
        guard = f.keyring.captureUnlockedSessionGuard();
        started.resolve();
        await held.promise;
        guard();
      }
    );
    void pending.catch(noop);
    await started.promise;
    abort.abort();
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
    expect(() => guard()).toThrow();
    held.resolve();
    await expect(pending).rejects.toThrow();
    noBuffers(f.keyring);
  } finally {
    held.resolve();
    await f.keyring.destroy();
  }
});

it('drops keys as soon as work ends even when the credential provider has not settled', async () => {
  const f = fixture();
  await f.initialize();
  const held = deferred(),
    finished = deferred();
  try {
    const pending = f.keyring.withSecretOperation(
      {
        async withSecret(_check, consume) {
          await consume(password);
          finished.resolve();
          await held.promise;
        },
      },
      options(),
      () => 'done'
    );
    await finished.promise;
    noBuffers(f.keyring);
    held.resolve();
    expect(await pending).toBe('done');
  } finally {
    held.resolve();
    await f.keyring.destroy();
  }
});

it('late cancelled credential work cannot clear a successor keyring public session', async () => {
  const f = fixture();
  await f.initialize();
  const held = deferred(),
    entered = deferred();
  const old = f.keyring.withSecretOperation(
    {
      async withSecret(_check, consume) {
        entered.resolve();
        await held.promise;
        await consume(password);
      },
    },
    options(),
    noop
  );
  void old.catch(noop);
  await entered.promise;
  await f.keyring.lockWallet();
  const successor = f.create();
  try {
    expect(await successor.unlock(password)).toEqual({ canLogin: true });
    const live = successor.capturePublicSessionGuard();
    held.resolve();
    await expect(old).rejects.toThrow();
    live();
    noBuffers(successor);
  } finally {
    held.resolve();
    await f.keyring.destroy();
    await successor.destroy();
  }
});

it('moves only public authority between operation-policy owners, preserving once-only transfer', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    const old = f.keyring.capturePublicSessionGuard();
    const transfer = await f.keyring.prepareSessionTransfer(target, noop);
    transfer.transfer();
    expect(f.keyring.hasPublicSession()).toBe(false);
    expect(target.hasPublicSession()).toBe(true);
    expect(() => old()).toThrow();
    expect(() => transfer.transfer()).toThrow('already');
    noBuffers(target);
    expect(
      await target.withSecretOperation(
        port,
        options(),
        async () => (await target.getSeed(password)).split(' ').length
      )
    ).toBe(12);
    noBuffers(target);
  } finally {
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('refuses a prepared authority transfer while a later secret operation is live', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create(),
    entered = deferred(),
    release = deferred();
  try {
    const transfer = await f.keyring.prepareSessionTransfer(target, noop);
    const signing = f.keyring.withSecretOperation(port, options(), async () => {
      const check = f.keyring.captureUnlockedSessionGuard();
      entered.resolve();
      await release.promise;
      check();
    });
    await entered.promise;
    expect(() => transfer.transfer()).toThrow('session changed');
    expect(f.keyring.hasPublicSession()).toBe(true);
    expect(target.hasPublicSession()).toBe(false);
    release.resolve();
    await signing;
    noBuffers(f.keyring);
    const fresh = await f.keyring.prepareSessionTransfer(target, noop);
    fresh.transfer();
    expect(f.keyring.hasPublicSession()).toBe(false);
    expect(target.hasPublicSession()).toBe(true);
  } finally {
    release.resolve();
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('requires a fresh operation for the existing software signer and preserves its result', async () => {
  const f = fixture();
  await f.initialize();
  const address = f.keyring.getActiveAccount().activeAccount.address;
  const signing = () =>
    f.keyring.ethereumTransaction.signPersonalMessage(
      ['0x11', address],
      options()
    );
  try {
    await expect(signing()).rejects.toThrow('secret operation');
    const signature = await f.keyring.withSecretOperation(
      port,
      options(),
      signing
    );
    expect(
      recoverPersonalSignature({ data: '0x11', signature }).toLowerCase()
    ).toBe(address.toLowerCase());
    noBuffers(f.keyring);
    await expect(signing()).rejects.toThrow('secret operation');
  } finally {
    await f.keyring.destroy();
  }
});

it('keeps an owned public UTXO fee read current across a secret operation', async () => {
  const f = fixture();
  await f.initialize();
  const response = deferred(),
    reading = deferred();
  f.state.activeNetwork = {
    kind: INetworkType.Syscoin,
    chainId: 57,
    slip44: 57,
    label: 'Syscoin',
    currency: 'sys',
    url: 'https://offline.invalid',
  };
  const read = {
    ...options(),
    fetch: (async () => {
      reading.resolve();
      await response.promise;
      return { ok: true, json: async () => ({ result: '0.001' }) };
    }) as unknown as typeof fetch,
  };
  try {
    const mock = jest.requireMock('syscoinjs-lib');
    const actual = jest.requireActual('syscoinjs-lib');
    mock.utils.fetchEstimateFee.mockImplementationOnce(
      actual.utils.fetchEstimateFee
    );
    const fee = f.keyring.syscoinTransaction.getRecommendedFee(
      f.state.activeNetwork.url,
      read
    );
    await reading.promise;
    await f.keyring.withSecretOperation(port, options(), () => undefined);
    noBuffers(f.keyring);
    response.resolve();
    expect(await fee).toBe(0.001 / 1024);
  } finally {
    response.resolve();
    await f.keyring.destroy();
  }
});

it('authenticates from locked and hydrates within one operation before keeping public authority', async () => {
  const f = fixture();
  await f.initialize();
  await f.keyring.lockWallet();
  try {
    const profile = await f.keyring.withSecretOperation(
      port,
      options(),
      async (secret) => {
        expect(secret).toBe(password);
        expect(f.keyring.isUnlocked()).toBe(true);
        return f.keyring.getPrivateRecordProfileId();
      }
    );
    expect(profile).toMatch(/^0x[0-9a-f]+$/);
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
    await f.keyring.lockWallet();
    await expect(
      f.keyring.withSecretOperation(port, options(), () => {
        throw Error('hydrate failed');
      })
    ).rejects.toThrow('hydrate failed');
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(false);
  } finally {
    await f.keyring.destroy();
  }
});
