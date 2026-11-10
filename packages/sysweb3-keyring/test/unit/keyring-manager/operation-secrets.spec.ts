import { recoverPersonalSignature } from '@metamask/eth-sig-util';

import { transferPrivateRecordAccess } from '../../../src/private-records';
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

it('keeps only domain-limited record keys after spending material is retired', async () => {
  const f = fixture();
  await f.initialize();
  try {
    await expect(
      f.keyring.createPrivateRecordAccess(['test.tx.records'], {
        transferable: false,
      })
    ).rejects.toThrow();
    const access = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(['test.tx.records'], {
        transferable: false,
      })
    );
    noBuffers(f.keyring);
    expect(Object.keys(access).sort()).toEqual([
      'decryptPrivateRecord',
      'dispose',
      'encryptPrivateRecord',
      'getPrivateRecordProfileId',
    ]);
    const plaintext = new Uint8Array([1, 2, 3]);
    const envelope = await access.encryptPrivateRecord({
      domain: 'test.tx.records',
      recordId: 'transaction',
      plaintext,
    });
    expect(
      await access.decryptPrivateRecord({
        domain: 'test.tx.records',
        recordId: 'transaction',
        envelope,
      })
    ).toEqual(plaintext);
    await expect(
      access.encryptPrivateRecord({
        domain: 'private.notes',
        recordId: 'note',
        plaintext,
      })
    ).rejects.toThrow('domain not authorized');
    noBuffers(f.keyring);
    expect(
      await f.keyring.withSecretOperation(port, options(), () =>
        f.keyring.decryptPrivateRecord({
          domain: 'test.tx.records',
          recordId: 'transaction',
          envelope,
        })
      )
    ).toEqual(plaintext);
    await f.keyring.lockWallet();
    await expect(access.getPrivateRecordProfileId()).rejects.toThrow();
    await expect(
      access.decryptPrivateRecord({
        domain: 'test.tx.records',
        recordId: 'transaction',
        envelope,
      })
    ).rejects.toThrow();
  } finally {
    await f.keyring.destroy();
  }
});

const journalDomains = [
  'org.syscoin.pali.evm.signed.root.v1',
  'org.syscoin.pali.evm.signed.chunk.v1',
  'org.syscoin.pali.utxo.signed.root.v1',
  'org.syscoin.pali.utxo.signed.chunk.v1',
] as const;

it('moves already-derived journal keys, retires source facades and never reloads a mnemonic', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    const sourceAccess = await f.keyring.withSecretOperation(
      port,
      options(),
      () =>
        f.keyring.createPrivateRecordAccess(journalDomains, {
          transferable: true,
        })
    );
    const params = {
      domain: journalDomains[0],
      recordId: 'transaction',
      plaintext: new Uint8Array([1, 2, 3]),
    };
    const envelope = await sourceAccess.encryptPrivateRecord(params);
    const rootRead = jest
      .spyOn(target as any, 'privateRecordSession')
      .mockImplementation(() => {
        throw new Error('Mnemonic must not reopen');
      });
    const transfer = await f.keyring.prepareSessionTransfer(target, noop);
    transfer.transfer();
    await expect(sourceAccess.getPrivateRecordProfileId()).rejects.toThrow(
      'retired'
    );
    const targetAccess = target.getPrivateRecordAccess(
      [...journalDomains].reverse()
    );
    sourceAccess.dispose();
    await f.keyring.destroy();
    expect(
      await targetAccess.decryptPrivateRecord({ ...params, envelope })
    ).toEqual(params.plaintext);
    expect(rootRead).not.toHaveBeenCalled();
    expect(() => target.getPrivateRecordAccess([journalDomains[0]])).toThrow(
      'not initialized'
    );
    expect(() =>
      target.getPrivateRecordAccess([
        ...journalDomains,
        'org.syscoin.pali.privacy.notes.v1',
      ])
    ).toThrow('not initialized');
    expect(() =>
      target.getPrivateRecordAccess([journalDomains[0], journalDomains[0]])
    ).toThrow('Invalid record domains');
    noBuffers(f.keyring);
    noBuffers(target);
    await target.lockWallet();
    await expect(targetAccess.getPrivateRecordProfileId()).rejects.toThrow(
      'retired'
    );
    expect(() => target.getPrivateRecordAccess(journalDomains)).toThrow();
  } finally {
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('a return transfer revokes every old record facade while preserving the same v1 envelopes', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    const old = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(journalDomains, {
        transferable: true,
      })
    );
    const params = {
      domain: journalDomains[2],
      recordId: 'utxo',
      plaintext: new Uint8Array([4, 5, 6]),
    };
    const envelope = await old.encryptPrivateRecord(params);
    (await f.keyring.prepareSessionTransfer(target, noop)).transfer();
    const intermediate = target.getPrivateRecordAccess(journalDomains);
    (await target.prepareSessionTransfer(f.keyring, noop)).transfer();
    const current = f.keyring.getPrivateRecordAccess(journalDomains);
    old.dispose();
    intermediate.dispose();
    await target.destroy();
    expect(await current.decryptPrivateRecord({ ...params, envelope })).toEqual(
      params.plaintext
    );
    await expect(intermediate.encryptPrivateRecord(params)).rejects.toThrow(
      'retired'
    );
    await expect(old.encryptPrivateRecord(params)).rejects.toThrow('retired');
    noBuffers(f.keyring);
  } finally {
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('in-flight old record decrypt cannot deliver plaintext after a transfer', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  const entered = deferred(),
    release = deferred();
  let decoded: ArrayBuffer | undefined;
  try {
    const old = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(journalDomains, {
        transferable: true,
      })
    );
    const params = {
      domain: journalDomains[0],
      recordId: 'retained',
      plaintext: new Uint8Array([7, 8, 9]),
    };
    const envelope = await old.encryptPrivateRecord(params);
    const decrypt = globalThis.crypto.subtle.decrypt.bind(
      globalThis.crypto.subtle
    );
    const intercepted = jest
      .spyOn(globalThis.crypto.subtle, 'decrypt')
      .mockImplementation(async (...args) => {
        decoded = await decrypt(...args);
        entered.resolve();
        await release.promise;
        return decoded;
      });
    const reading = old.decryptPrivateRecord({ ...params, envelope });
    const rejected = expect(reading).rejects.toThrow('retired');
    await entered.promise;
    (await f.keyring.prepareSessionTransfer(target, noop)).transfer();
    release.resolve();
    await rejected;
    expect([...new Uint8Array(decoded!)]).toEqual([0, 0, 0]);
    intercepted.mockRestore();
    expect(
      await target
        .getPrivateRecordAccess(journalDomains)
        .decryptPrivateRecord({ ...params, envelope })
    ).toEqual(params.plaintext);
  } finally {
    release.resolve();
    jest.restoreAllMocks();
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('a disposed record grant cannot be retrieved or revived by transfer', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    const grant = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(journalDomains, {
        transferable: true,
      })
    );
    grant.dispose();
    expect(() => f.keyring.getPrivateRecordAccess(journalDomains)).toThrow(
      'not initialized'
    );
    (await f.keyring.prepareSessionTransfer(target, noop)).transfer();
    expect(() => target.getPrivateRecordAccess(journalDomains)).toThrow(
      'not initialized'
    );
  } finally {
    await f.keyring.destroy();
    await target.destroy();
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

it('requires an explicit transfer policy and retires private note grants during public transfer', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    await expect(
      f.keyring.withSecretOperation(port, options(), () =>
        f.keyring.createPrivateRecordAccess(journalDomains, undefined as never)
      )
    ).rejects.toThrow('Explicit record transfer policy');
    const { journal, notes } = await f.keyring.withSecretOperation(
      port,
      options(),
      async () => ({
        journal: await f.keyring.createPrivateRecordAccess(journalDomains, {
          transferable: true,
        }),
        notes: await f.keyring.createPrivateRecordAccess(
          ['org.syscoin.pali.privacy.notes.v1'],
          { transferable: false }
        ),
      })
    );
    (await f.keyring.prepareSessionTransfer(target, noop)).transfer();
    await expect(notes.getPrivateRecordProfileId()).rejects.toThrow('retired');
    await expect(journal.getPrivateRecordProfileId()).rejects.toThrow(
      'retired'
    );
    expect(() =>
      target.getPrivateRecordAccess(['org.syscoin.pali.privacy.notes.v1'])
    ).toThrow('not initialized');
    expect(
      await target
        .getPrivateRecordAccess(journalDomains)
        .getPrivateRecordProfileId()
    ).toMatch(/^0x[0-9a-f]{64}$/);
    noBuffers(f.keyring);
    noBuffers(target);
  } finally {
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('raw helper imports cannot detach a live record grant from the SDK owner', async () => {
  const f = fixture();
  await f.initialize();
  try {
    const access = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(journalDomains, {
        transferable: true,
      })
    );
    expect(() => transferPrivateRecordAccess(access, {}, {}, noop)).toThrow(
      'owner mismatch'
    );
    expect(f.keyring.getPrivateRecordAccess(journalDomains)).toBe(access);
    await f.keyring.lockWallet();
    await expect(access.getPrivateRecordProfileId()).rejects.toThrow('retired');
  } finally {
    await f.keyring.destroy();
  }
});

it('private action grants cannot be recovered by the public cached lookup', async () => {
  const f = fixture();
  await f.initialize();
  try {
    const domains = ['org.syscoin.pali.privacy.notes.v1'];
    const access = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(domains, { transferable: false })
    );
    expect(() => f.keyring.getPrivateRecordAccess(domains)).toThrow(
      'not initialized'
    );
    expect(await access.getPrivateRecordProfileId()).toMatch(/^0x/);
    access.dispose();
    expect(() => f.keyring.getPrivateRecordAccess(domains)).toThrow(
      'not initialized'
    );
  } finally {
    await f.keyring.destroy();
  }
});

it('record capabilities do not trust an overridden public-session guard', async () => {
  const f = fixture();
  await f.initialize();
  const target = f.create();
  try {
    (f.keyring as any).capturePublicSessionGuard = () => noop;
    (target as any).capturePublicSessionGuard = () => noop;
    const access = await f.keyring.withSecretOperation(port, options(), () =>
      f.keyring.createPrivateRecordAccess(journalDomains, {
        transferable: true,
      })
    );
    (await f.keyring.prepareSessionTransfer(target, noop)).transfer();
    const moved = target.getPrivateRecordAccess(journalDomains);
    await expect(access.getPrivateRecordProfileId()).rejects.toThrow('retired');
    await target.lockWallet();
    (target as any).hasPublicSession = () => true;
    expect(() => target.getPrivateRecordAccess(journalDomains)).toThrow(
      'public session'
    );
    await expect(moved.getPrivateRecordProfileId()).rejects.toThrow('retired');
  } finally {
    await f.keyring.destroy();
    await target.destroy();
  }
});

it('refuses work when the host guard synchronously aborts immediately before the callback', async () => {
  const f = fixture();
  await f.initialize();
  const abort = new AbortController();
  let authenticated = false,
    afterAuthentication = 0;
  const unlockSession = (f.keyring as any).unlockSession.bind(f.keyring);
  const unlock = jest
    .spyOn(f.keyring as any, 'unlockSession')
    .mockImplementation(async (...args) => {
      const result = await unlockSession(...args);
      authenticated = true;
      return result;
    });
  const work = jest.fn();
  try {
    await expect(
      f.keyring.withSecretOperation(
        port,
        {
          signal: abort.signal,
          assertCurrent() {
            if (authenticated && ++afterAuthentication === 2) abort.abort();
          },
        },
        work
      )
    ).rejects.toThrow();
    expect(work).not.toHaveBeenCalled();
    noBuffers(f.keyring);
    expect(f.keyring.hasPublicSession()).toBe(true);
  } finally {
    unlock.mockRestore();
    await f.keyring.destroy();
  }
});
