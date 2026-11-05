import { createHash, webcrypto } from 'crypto';
import CryptoJS from 'crypto-js';

import {
  INetworkType,
  KeyringAccountType,
  SoftwareKeyring,
  createKeyringHost,
} from '../../../src/software';
import { VaultAuthenticationError } from '../../../src/storage-core';

import type {
  DeviceUnlockControls,
  DeviceUnlockCredential,
  DeviceUnlockVaultPair,
  KeyringStoragePort,
} from '../../../src/software';

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'device unlock synthetic fixture';
const newPassword = 'device unlock replacement fixture';
const current = () => undefined;
const hd = KeyringAccountType.HDAccount;

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function holdVaultRead(storage: KeyringStoragePort, readNumber: number) {
  const started = deferred<void>();
  const release = deferred<Error | undefined>();
  const get = jest.mocked(storage.get).getMockImplementation()!;
  let reads = 0;
  jest.mocked(storage.get).mockImplementation(async (key) => {
    const value = await get(key);
    if (key === 'vault' && ++reads === readNumber) {
      started.resolve();
      const error = await release.promise;
      if (error) throw error;
    }
    return value;
  });
  return { started: started.promise, release: release.resolve };
}

const rings: SoftwareKeyring[] = [];
afterEach(async () => {
  await Promise.all(rings.splice(0).map((ring) => ring.destroy()));
  jest.restoreAllMocks();
});

function fixture() {
  const records = new Map<string, any>();
  const readPair = jest.fn(async (): Promise<DeviceUnlockVaultPair | null> => {
    const vault = records.get('vault');
    const keys = records.get('vault-keys');
    if (!vault || !keys) return null;
    const pairFingerprint = createHash('sha256')
      .update(JSON.stringify([vault, keys]))
      .digest('hex');
    return { vault, keys, pairFingerprint };
  });
  const storage: KeyringStoragePort = {
    get: jest.fn(async (key) => records.get(key)),
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
    readDeviceUnlockVaultPair: readPair,
  };
  let saved: DeviceUnlockCredential | null = null;
  const readCredential = jest.fn(
    async () => saved && { ...saved, key: saved.key.slice() }
  );
  const writeCredential = jest.fn(
    async (credential: DeviceUnlockCredential, assertCurrent: () => void) => {
      assertCurrent();
      saved = { ...credential, key: credential.key.slice() };
    }
  );
  const state = {
    activeAccount: { id: 0, type: hd },
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
  } as any;
  const createHost = () =>
    createKeyringHost(storage, {
      deviceUnlock: { readCredential, writeCredential },
    });
  const attach = (ring: SoftwareKeyring) => {
    rings.push(ring);
    ring.setVaultStateGetter(() => state);
    return ring;
  };
  const open = (host = createHost()) => {
    const receive = jest.fn<void, [DeviceUnlockControls]>();
    const ring = attach(
      new SoftwareKeyring(host, { receiveDeviceUnlock: receive })
    );
    expect(receive).toHaveBeenCalledTimes(1);
    return { ring, controls: receive.mock.calls[0][0] };
  };
  const create = async (walletPassword = password, host = createHost()) => {
    const result = open(host);
    state.accounts.HDAccount[0] = await result.ring.initializeWalletSecurely(
      mnemonic,
      walletPassword
    );
    return result;
  };
  return {
    records,
    storage,
    readPair,
    readCredential,
    writeCredential,
    createHost,
    attach,
    open,
    create,
  };
}

it('provides no addressable device capability to an unconfigured host', async () => {
  const f = fixture();
  const host = createKeyringHost(f.storage);
  const ring = new SoftwareKeyring(host);
  rings.push(ring);
  const receive = jest.fn();
  expect(
    () => new SoftwareKeyring(host, { receiveDeviceUnlock: receive })
  ).toThrow('Device unlock is unavailable in this host');
  expect(receive).not.toHaveBeenCalled();
  for (const name of [
    'issue',
    'resume',
    'createDeviceUnlockControls',
    'installVaultSession',
    'recreateSessionFromVault',
    'replaceSessionBuffers',
    'acceptSessionFrom',
  ]) {
    expect(Reflect.has(ring, name)).toBe(false);
    expect(Reflect.has(host, name)).toBe(false);
  }
  expect('receiveSessionOwnership' in ring).toBe(false);
  expect(f.readPair).not.toHaveBeenCalled();
  expect(f.readCredential).not.toHaveBeenCalled();

  expect(() =>
    createKeyringHost(
      { ...f.storage, readDeviceUnlockVaultPair: undefined },
      { deviceUnlock: f }
    )
  ).toThrow('Device unlock requires an atomic vault pair reader');
  expect(receive).not.toHaveBeenCalled();
});

it('authenticates issue, resumes cold from the same real pair and still requires a fresh export password', async () => {
  const f = fixture();
  const { ring, controls } = await f.create();
  const before = JSON.stringify([...f.records]);
  const profile = await ring.getPrivateRecordProfileId();
  const accountKey = await ring.getPrivateKeyByAccountId(0, hd, password);
  expect(accountKey).toBeTruthy();
  expect(Object.isFrozen(controls)).toBe(true);
  expect(Reflect.ownKeys(controls)).toEqual(['issue', 'resume']);

  await expect(controls.issue('wrong password', current)).resolves.toBe(false);
  expect(f.writeCredential).not.toHaveBeenCalled();
  expect(ring.isUnlocked()).toBe(true);
  await expect(controls.issue(password, current)).resolves.toBe(true);
  const written = f.writeCredential.mock.calls[0][0];
  expect(written.pairFingerprint).toBe((await f.readPair())?.pairFingerprint);
  expect(written.key).toEqual(new Uint8Array(32));
  expect(f.readCredential).not.toHaveBeenCalled();
  await ring.destroy();

  const cold = f.open();
  expect(cold.ring.isUnlocked()).toBe(false);
  await expect(cold.controls.resume(current)).resolves.toBe(true);
  expect(cold.ring.isUnlocked()).toBe(true);
  expect(typeof cold.ring.syscoinTransaction.getRecommendedFee).toBe(
    'function'
  );
  expect(await cold.ring.getPrivateRecordProfileId()).toBe(profile);
  const copiedCredential = await f.readCredential.mock.results[0].value;
  expect(copiedCredential.key).toEqual(new Uint8Array(32));
  const storedCredential = await f.readCredential();
  const keyAsPassword = Buffer.from(storedCredential!.key).toString('hex');
  storedCredential!.key.fill(0);
  await expect(cold.ring.getSeed(keyAsPassword)).rejects.toThrow(
    'Invalid password'
  );
  await expect(
    cold.ring.getPrivateKeyByAccountId(0, hd, keyAsPassword)
  ).rejects.toThrow('Invalid password');
  await expect(cold.ring.getSeed(password)).resolves.toBe(mnemonic);
  await expect(
    cold.ring.getPrivateKeyByAccountId(0, hd, password)
  ).resolves.toBe(accountKey);
  expect(JSON.stringify([...f.records])).toBe(before);
});

for (const revocation of ['host guard', 'keyring lock'] as const) {
  it(`reports a definitive password refusal for the same pair after ${revocation}`, async () => {
    const f = fixture();
    const { ring, controls } = await f.create();
    const rereadStarted = deferred<void>();
    const release = deferred<void>();
    const readPair = f.readPair.getMockImplementation()!;
    f.readPair
      .mockImplementationOnce(readPair)
      .mockImplementationOnce(async () => {
        const pair = await readPair();
        rereadStarted.resolve();
        await release.promise;
        return pair;
      });
    let active = true;
    const issuing = controls.issue(newPassword, () => {
      if (!active) throw new Error('Host owner retired');
    });
    try {
      // With a wrong password, this second read is reached only after AEAD rejects.
      await rereadStarted.promise;
      if (revocation === 'host guard') active = false;
      else await ring.lockWallet();
    } finally {
      release.resolve();
    }
    await expect(issuing).resolves.toBe(false);
    expect(f.writeCredential).not.toHaveBeenCalled();
    expect(ring.isUnlocked()).toBe(revocation === 'host guard');
  });
}

it('rejects a replaced pair even if the old key is relabelled with the new fingerprint', async () => {
  const f = fixture();
  const { ring, controls } = await f.create();
  await expect(controls.issue(password, current)).resolves.toBe(true);
  const old = (await f.readCredential())!;
  await ring.lockWallet();

  const replacement = fixture();
  await replacement.create(newPassword);
  for (const key of ['vault', 'vault-keys']) {
    f.records.set(key, replacement.records.get(key));
  }
  const before = JSON.stringify([...f.records]);
  await expect(controls.resume(current)).resolves.toBe(false);
  expect(ring.isUnlocked()).toBe(false);

  f.readCredential.mockResolvedValueOnce({
    pairFingerprint: (await f.readPair())!.pairFingerprint,
    key: old.key,
  });
  await expect(controls.resume(current)).resolves.toBe(false);
  expect(old.key).toEqual(new Uint8Array(32));
  expect(ring.isUnlocked()).toBe(false);
  expect(JSON.stringify([...f.records])).toBe(before);
  await expect(ring.unlock(newPassword)).resolves.toEqual({ canLogin: true });
});

it.each(['vault', 'salt'])(
  'rechecks exact %s bytes after a held protected read, even with a stale fingerprint',
  async (field) => {
    const f = fixture();
    const { ring, controls } = await f.create();
    await expect(controls.issue(password, current)).resolves.toBe(true);
    const pair = (await f.readPair())!;
    const credential = (await f.readCredential())!;
    await ring.lockWallet();
    const started = deferred<void>();
    const answer = deferred<DeviceUnlockCredential>();
    f.readCredential.mockImplementationOnce(() => {
      started.resolve();
      return answer.promise;
    });
    const resume = controls.resume(current);
    await started.promise;
    f.readPair.mockResolvedValueOnce({
      ...pair,
      vault: field === 'vault' ? pair.vault + ' ' : pair.vault,
      keys: field === 'salt' ? { salt: '42'.repeat(16) } : pair.keys,
    });
    answer.resolve(credential);
    await expect(resume).rejects.toThrow('Device unlock vault changed');
    expect(credential.key).toEqual(new Uint8Array(32));
    expect(ring.isUnlocked()).toBe(false);
  }
);

it.each([false, true])(
  'revokes a held resume on lock without affecting a newer password session (%s)',
  async (unlockAgain) => {
    const f = fixture();
    const { ring, controls } = await f.create();
    await expect(controls.issue(password, current)).resolves.toBe(true);
    const credential = (await f.readCredential())!;
    await ring.lockWallet();
    const started = deferred<void>();
    const answer = deferred<DeviceUnlockCredential>();
    f.readCredential.mockImplementationOnce(() => {
      started.resolve();
      return answer.promise;
    });
    const resume = controls.resume(current);
    await started.promise;
    await expect(controls.resume(current)).rejects.toThrow('operation is busy');
    await ring.lockWallet();
    if (unlockAgain)
      await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    answer.resolve(credential);
    await expect(resume).rejects.toThrow('Device unlock session changed');
    expect(credential.key).toEqual(new Uint8Array(32));
    expect(ring.isUnlocked()).toBe(unlockAgain);
  }
);

it('checks enrollment authority again at protected write and retires saved controls on destroy', async () => {
  const f = fixture();
  const { ring, controls } = await f.create();
  const started = deferred<void>();
  const gate = deferred<void>();
  let permitted = true;
  let saved = false;
  f.writeCredential.mockImplementationOnce(
    async (_credential, assertCurrent) => {
      started.resolve();
      await gate.promise;
      assertCurrent();
      saved = true;
    }
  );
  const enrollment = controls.issue(password, () => {
    if (!permitted) throw new Error('Host revoked');
  });
  await started.promise;
  permitted = false;
  gate.resolve();
  await expect(enrollment).rejects.toThrow('Host revoked');
  expect(saved).toBe(false);
  expect(f.writeCredential.mock.calls[0][0].key).toEqual(new Uint8Array(32));
  expect(ring.isUnlocked()).toBe(true);

  await ring.destroy();
  f.readPair.mockClear();
  await expect(controls.resume(current)).rejects.toThrow(
    'Device unlock session changed'
  );
  await expect(controls.issue(password, current)).rejects.toThrow(
    'Device unlock session changed'
  );
  expect(f.readPair).not.toHaveBeenCalled();
});

it('moves the host owner on transfer and retires the source device controls', async () => {
  const f = fixture();
  const host = f.createHost();
  const source = await f.create(password, host);
  await expect(source.controls.issue(password, current)).resolves.toBe(true);
  const target = f.attach(new SoftwareKeyring(host));
  const fresh = f.open(host);
  const started = deferred<void>();
  const release = deferred<void>();
  let wrote = false;
  f.writeCredential.mockImplementationOnce(
    async (_credential, assertCurrent) => {
      started.resolve();
      await release.promise;
      assertCurrent();
      wrote = true;
    }
  );
  const issuing = source.controls.issue(password, current);
  await started.promise;

  source.ring.transferSessionTo(target);
  release.resolve();
  await expect(issuing).rejects.toThrow('Device unlock session changed');
  expect(wrote).toBe(false);
  expect(source.ring.isUnlocked()).toBe(false);
  expect(target.isUnlocked()).toBe(true);
  await expect(target.getSeed(password)).resolves.toBe(mnemonic);
  f.readCredential.mockClear();
  await expect(source.controls.resume(current)).rejects.toThrow(
    'Device unlock session changed'
  );
  await expect(fresh.controls.resume(current)).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(f.readCredential).not.toHaveBeenCalled();

  await source.ring.lockWallet();
  await expect(fresh.controls.resume(current)).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(target.isUnlocked()).toBe(true);

  await target.lockWallet();
  await expect(source.controls.issue(password, current)).rejects.toThrow(
    'Device unlock session changed'
  );
  await expect(fresh.controls.resume(current)).resolves.toBe(true);
  await source.ring.destroy();
  expect(fresh.ring.isUnlocked()).toBe(true);
});

it('refuses a held device resume when a password unlock on a receiver-free sibling wins', async () => {
  const f = fixture();
  const host = f.createHost();
  const device = await f.create(password, host);
  await expect(device.controls.issue(password, current)).resolves.toBe(true);
  const credential = (await f.readCredential())!;
  await device.ring.lockWallet();
  const started = deferred<void>();
  const release = deferred<DeviceUnlockCredential>();
  f.readCredential.mockImplementationOnce(() => {
    started.resolve();
    return release.promise;
  });
  const resume = device.controls.resume(current);
  await started.promise;

  const winner = f.attach(new SoftwareKeyring(host));
  await expect(winner.unlock(password)).resolves.toEqual({ canLogin: true });
  release.resolve(credential);
  await expect(resume).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(credential.key).toEqual(new Uint8Array(32));
  expect(device.ring.isUnlocked()).toBe(false);
  expect(winner.isUnlocked()).toBe(true);
  await expect(winner.getSeed(password)).resolves.toBe(mnemonic);
});

it('keeps a device winner through a competing password unlock and loser cleanup', async () => {
  const f = fixture();
  const host = f.createHost();
  const device = await f.create(password, host);
  await expect(device.controls.issue(password, current)).resolves.toBe(true);
  await device.ring.lockWallet();

  const contender = f.attach(new SoftwareKeyring(host));
  const get = jest.mocked(f.storage.get).getMockImplementation()!;
  const started = deferred<void>();
  const release = deferred<void>();
  jest.spyOn(f.storage, 'get').mockImplementationOnce(async (key) => {
    expect(key).toBe('vault-keys');
    started.resolve();
    await release.promise;
    return get(key);
  });
  const unlocking = contender.unlock(password);
  await started.promise;

  await expect(device.controls.resume(current)).resolves.toBe(true);
  release.resolve();
  await expect(unlocking).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(contender.isUnlocked()).toBe(false);
  const fresh = f.open(host);
  await expect(fresh.controls.resume(current)).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  await contender.lockWallet();
  await contender.destroy();
  await expect(fresh.controls.resume(current)).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(device.ring.isUnlocked()).toBe(true);
  await expect(device.ring.getSeed(password)).resolves.toBe(mnemonic);

  await device.ring.destroy();
  await expect(fresh.controls.resume(current)).resolves.toBe(true);
  expect(fresh.ring.isUnlocked()).toBe(true);
});

it.each([
  ['first read', 1, undefined],
  ['second read', 2, undefined],
  ['second read rejection', 2, new Error('Vault temporarily unavailable')],
] as const)(
  'preserves the same-ring device winner after a held password %s',
  async (_label, readNumber, failure) => {
    const f = fixture();
    const { ring, controls } = await f.create();
    await expect(controls.issue(password, current)).resolves.toBe(true);
    await ring.lockWallet();
    const before = JSON.stringify([...f.records]);
    const held = holdVaultRead(f.storage, readNumber);
    const pending = ring.unlock(password);
    await held.started;

    await expect(controls.resume(current)).resolves.toBe(true);
    const winner = (ring as any).sessionPassword;
    const winnerMnemonic = (ring as any).sessionMnemonic;
    held.release(failure);
    const outcome = await pending.catch((error: unknown) => error);
    expect(ring.isUnlocked()).toBe(true);
    expect((ring as any).sessionPassword).toBe(winner);
    expect((ring as any).sessionMnemonic).toBe(winnerMnemonic);
    expect(winner.isCleared()).toBe(false);
    expect(winnerMnemonic.isCleared()).toBe(false);
    await expect(ring.getSeed(password)).resolves.toBe(mnemonic);
    expect(JSON.stringify([...f.records])).toBe(before);
    expect(outcome).toEqual(new Error('Wallet unlock session changed'));
  }
);

it.each([
  'lock',
  'changed pair',
  'pair read error',
  'authentication-shaped pair read error',
] as const)(
  'classifies opted-in password refusal after %s',
  async (interruption) => {
    const f = fixture();
    const { ring } = await f.create();
    await ring.lockWallet();
    const changed = interruption === 'changed pair' ? fixture() : undefined;
    if (changed) await changed.create(newPassword);

    const rejected = deferred<unknown>();
    const release = deferred<void>();
    const decrypt = webcrypto.subtle.decrypt.bind(webcrypto.subtle);
    jest
      .spyOn(webcrypto.subtle, 'decrypt')
      .mockImplementationOnce(async (...args) => {
        try {
          return await decrypt(...args);
        } catch (error) {
          rejected.resolve(error);
          await release.promise;
          throw error;
        }
      });

    const misleading = interruption === 'authentication-shaped pair read error';
    const unavailable = misleading
      ? new VaultAuthenticationError()
      : new Error('Atomic vault pair temporarily unavailable');
    const unlocking = ring.unlock(newPassword);
    try {
      await expect(rejected.promise).resolves.toMatchObject({
        name: 'OperationError',
      });
      if (interruption === 'lock') await ring.lockWallet();
      if (changed) {
        f.records.set('vault', changed.records.get('vault'));
        f.records.set('vault-keys', changed.records.get('vault-keys'));
      }
      if (interruption === 'pair read error' || misleading)
        f.readPair.mockRejectedValueOnce(unavailable);
    } finally {
      release.resolve();
    }
    if (interruption === 'lock')
      await expect(unlocking).resolves.toEqual({ canLogin: false });
    else if (interruption === 'changed pair')
      await expect(unlocking).rejects.toThrow('Wallet unlock vault changed');
    else if (misleading)
      await expect(unlocking).rejects.toThrow(
        'Wallet unlock vault read failed'
      );
    else await expect(unlocking).rejects.toBe(unavailable);
    expect(ring.isUnlocked()).toBe(false);
    expect(f.readPair).toHaveBeenCalledTimes(1);
    expect(f.writeCredential).not.toHaveBeenCalled();
  }
);

it('keeps ordinary password refusal on the default host without a pair read', async () => {
  const f = fixture();
  const { ring } = await f.create();
  await ring.lockWallet();
  const plain = f.attach(
    new SoftwareKeyring(
      createKeyringHost({ ...f.storage, readDeviceUnlockVaultPair: undefined })
    )
  );
  await expect(plain.unlock(newPassword)).resolves.toEqual({ canLogin: false });
  expect(f.readPair).not.toHaveBeenCalled();
  expect(plain.isUnlocked()).toBe(false);
});

it.each(['explicit lock', 'sibling unlock and lock'])(
  'does not reopen a held password unlock after %s',
  async (interruption) => {
    const f = fixture();
    const host = f.createHost();
    const { ring, controls } = await f.create(password, host);
    await expect(controls.issue(password, current)).resolves.toBe(true);
    await ring.lockWallet();
    const held = holdVaultRead(f.storage, 2);
    const pending = ring.unlock(password);
    await held.started;

    if (interruption === 'explicit lock') {
      await ring.lockWallet();
    } else {
      const sibling = f.open(host);
      await expect(sibling.controls.resume(current)).resolves.toBe(true);
      await sibling.ring.lockWallet();
    }
    held.release(undefined);
    const outcome = await pending.catch((error: unknown) => error);
    expect(ring.isUnlocked()).toBe(false);
    expect(outcome).toEqual(new Error('Wallet unlock session changed'));
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
  }
);

it.each(['newly installed', 'unchanged'])(
  'completes a current held password read and clears %s buffers on operational failure',
  async (sessionKind) => {
    const f = fixture();
    const { ring } = await f.create();
    await ring.lockWallet();
    const held = holdVaultRead(f.storage, 2);
    const pending = ring.unlock(password);
    await held.started;
    held.release(undefined);
    await expect(pending).resolves.toEqual({ canLogin: true });
    if (sessionKind === 'newly installed') await ring.lockWallet();

    let passwordBuffer: any;
    let mnemonicBuffer: any;
    const error = new Error('Account state unavailable');
    ring.setVaultStateGetter(() => {
      passwordBuffer = (ring as any).sessionPassword;
      mnemonicBuffer = (ring as any).sessionMnemonic;
      throw error;
    });
    await expect(ring.unlock(password)).rejects.toBe(error);
    expect(passwordBuffer.isCleared()).toBe(true);
    expect(mnemonicBuffer.isCleared()).toBe(true);
    expect(ring.isUnlocked()).toBe(false);
  }
);

it('rechecks password ownership after the session install continuation', async () => {
  const f = fixture();
  const { ring } = await f.create();
  await ring.lockWallet();
  const locked = deferred<boolean>();
  const encrypt = CryptoJS.AES.encrypt.bind(CryptoJS.AES);
  jest.spyOn(CryptoJS.AES, 'encrypt').mockImplementationOnce((...args) => {
    queueMicrotask(() => {
      const wasUnlocked = ring.isUnlocked();
      void ring.lockWallet().then(() => locked.resolve(wasUnlocked));
    });
    return encrypt(...args);
  });
  await expect(ring.unlock(password)).rejects.toThrow(
    'Wallet unlock session changed'
  );
  await expect(locked.promise).resolves.toBe(true);
  expect(ring.isUnlocked()).toBe(false);
});

it('clears the installed password buffers if the restore diagnostic throws', async () => {
  const f = fixture();
  const { ring } = await f.create();
  await ring.lockWallet();
  const error = new Error('Restore diagnostic unavailable');
  let passwordBuffer: any;
  let mnemonicBuffer: any;
  const log = jest.spyOn(console, 'log').mockImplementation((message) => {
    if (message === '[KeyringManager] Session data recreated from vault') {
      passwordBuffer = (ring as any).sessionPassword;
      mnemonicBuffer = (ring as any).sessionMnemonic;
      throw error;
    }
  });
  const outcome = await ring.unlock(password).catch((error: unknown) => error);
  expect(ring.isUnlocked()).toBe(false);
  expect(outcome).toBe(error);
  expect(passwordBuffer.isCleared()).toBe(true);
  expect(mnemonicBuffer.isCleared()).toBe(true);
  log.mockRestore();
  await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
});

it('rechecks legacy metadata admission after copying a host storage record', async () => {
  const f = fixture();
  const { ring } = await f.create();
  await ring.lockWallet();
  const { salt } = f.records.get('vault-keys');
  const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
    keySize: 256 / 32,
    iterations: 20000,
    hasher: CryptoJS.algo.SHA512,
  }).toString();
  const vault = CryptoJS.AES.encrypt(
    JSON.stringify({ mnemonic }),
    key
  ).toString();
  const vaultKeys = {
    salt,
    get metadata() {
      void ring.lockWallet();
      return 'fixture metadata';
    },
  };
  f.records.set('vault-keys', vaultKeys);
  f.records.set('vault', vault);
  const writes = jest.spyOn(f.storage, 'set');
  const outcome = await ring.unlock(password).catch((error: unknown) => error);
  expect(writes).not.toHaveBeenCalled();
  expect(f.records.get('vault-keys')).toBe(vaultKeys);
  expect(f.records.get('vault')).toBe(vault);
  expect(ring.isUnlocked()).toBe(false);
  expect(outcome).toEqual(new Error('Wallet unlock session changed'));
});

it('refuses to dispatch an opted-in legacy migration after revocation during encryption', async () => {
  const f = fixture();
  const { ring } = await f.create();
  await ring.lockWallet();
  f.records.set('vault-keys', {
    ...f.records.get('vault-keys'),
    currentSessionSalt: '44'.repeat(16),
  });
  f.records.set(
    'vault',
    CryptoJS.AES.encrypt(JSON.stringify({ mnemonic }), password).toString()
  );
  const before = JSON.stringify([...f.records]);
  const writes = jest.spyOn(f.storage, 'set');
  const started = deferred<void>();
  const release = deferred<void>();
  const encrypt = webcrypto.subtle.encrypt.bind(webcrypto.subtle);
  jest
    .spyOn(webcrypto.subtle, 'encrypt')
    .mockImplementationOnce(async (...args) => {
      started.resolve();
      await release.promise;
      return encrypt(...args);
    });
  const pending = ring.unlock(password);
  await started.promise;
  await ring.lockWallet();
  release.resolve();
  const outcome = await pending.catch((error: unknown) => error);
  expect(writes).not.toHaveBeenCalled();
  expect(JSON.stringify([...f.records])).toBe(before);
  expect(ring.isUnlocked()).toBe(false);
  expect(outcome).toEqual(new Error('Wallet unlock session changed'));
  await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
  await expect(ring.getSeed(password)).resolves.toBe(mnemonic);
});

it('revokes a held device resume when a sibling takes and releases ownership between checks', async () => {
  const f = fixture();
  const host = f.createHost();
  const device = await f.create(password, host);
  await expect(device.controls.issue(password, current)).resolves.toBe(true);
  const credential = (await f.readCredential())!;
  await device.ring.lockWallet();

  const started = deferred<void>();
  const answer = deferred<DeviceUnlockCredential>();
  f.readCredential.mockImplementationOnce(() => {
    started.resolve();
    return answer.promise;
  });
  const resume = device.controls.resume(current);
  await started.promise;

  const sibling = f.attach(new SoftwareKeyring(host));
  await expect(sibling.unlock(password)).resolves.toEqual({ canLogin: true });
  expect(sibling.isUnlocked()).toBe(true);
  await sibling.lockWallet();
  expect(sibling.isUnlocked()).toBe(false);
  answer.resolve(credential);
  await expect(resume).rejects.toThrow('Device unlock session changed');
  expect(device.ring.isUnlocked()).toBe(false);
  expect(credential.key).toEqual(new Uint8Array(32));
  await expect(device.controls.resume(current)).resolves.toBe(true);
});

it('keeps a held owner enrollment current through a nonowner lock and destroy', async () => {
  const f = fixture();
  const host = f.createHost();
  const owner = await f.create(password, host);
  const sibling = f.attach(new SoftwareKeyring(host));

  const started = deferred<void>();
  const release = deferred<void>();
  const write = f.writeCredential.getMockImplementation()!;
  f.writeCredential.mockImplementationOnce(
    async (credential, assertCurrent) => {
      started.resolve();
      await release.promise;
      await write(credential, assertCurrent);
    }
  );
  const enrollment = owner.controls.issue(password, current);
  await started.promise;
  await expect(sibling.unlock(password)).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  await sibling.lockWallet();
  await sibling.destroy();
  release.resolve();
  await expect(enrollment).resolves.toBe(true);
  expect(owner.ring.isUnlocked()).toBe(true);
});

it('lets only one fresh device receiver install from simultaneous protected reads', async () => {
  const f = fixture();
  const host = f.createHost();
  const enrolled = await f.create(password, host);
  await expect(enrolled.controls.issue(password, current)).resolves.toBe(true);
  const firstCredential = (await f.readCredential())!;
  const secondCredential = (await f.readCredential())!;
  await enrolled.ring.lockWallet();

  const first = f.open(host);
  const second = f.open(host);
  const firstStarted = deferred<void>();
  const secondStarted = deferred<void>();
  const firstRead = deferred<DeviceUnlockCredential>();
  const secondRead = deferred<DeviceUnlockCredential>();
  f.readCredential
    .mockImplementationOnce(() => {
      firstStarted.resolve();
      return firstRead.promise;
    })
    .mockImplementationOnce(() => {
      secondStarted.resolve();
      return secondRead.promise;
    });
  const firstResume = first.controls.resume(current);
  await firstStarted.promise;
  const secondResume = second.controls.resume(current);
  await secondStarted.promise;

  firstRead.resolve(firstCredential);
  await expect(firstResume).resolves.toBe(true);
  secondRead.resolve(secondCredential);
  await expect(secondResume).rejects.toThrow(
    'Wallet session is owned by another keyring'
  );
  expect(first.ring.isUnlocked()).toBe(true);
  expect(second.ring.isUnlocked()).toBe(false);
  expect(secondCredential.key).toEqual(new Uint8Array(32));
});

it('requires an acknowledged protected write and leaves the live session unchanged on failure', async () => {
  const f = fixture();
  const { ring, controls } = await f.create();
  const before = JSON.stringify([...f.records]);
  f.writeCredential.mockImplementationOnce(
    async (credential, assertCurrent) => {
      assertCurrent();
      f.readCredential.mockResolvedValueOnce({
        ...credential,
        key: credential.key.slice(),
      });
      throw new Error('Protected write acknowledgement lost');
    }
  );
  await expect(controls.issue(password, current)).rejects.toThrow(
    'Protected write acknowledgement lost'
  );
  expect(f.writeCredential.mock.calls[0][0].key).toEqual(new Uint8Array(32));
  f.writeCredential.mockResolvedValueOnce(false as unknown as void);
  await expect(controls.issue(password, current)).rejects.toThrow(
    'Device unlock credential write was not acknowledged'
  );
  expect(f.writeCredential.mock.calls[1][0].key).toEqual(new Uint8Array(32));
  expect(ring.isUnlocked()).toBe(true);
  expect(JSON.stringify([...f.records])).toBe(before);
});

it('rejects an asynchronous lifecycle guard before protected I/O', async () => {
  const f = fixture();
  const { controls } = await f.create();
  await expect(
    controls.issue(password, async () => {
      throw new Error('async guard');
    })
  ).rejects.toThrow('guard must return undefined synchronously');
  expect(f.readPair).not.toHaveBeenCalled();
  expect(f.writeCredential).not.toHaveBeenCalled();
});

it('refuses valid CBC in both device operations while preserving password compatibility', async () => {
  const f = fixture();
  const { ring, controls } = await f.create();
  await expect(controls.issue(password, current)).resolves.toBe(true);
  const old = (await f.readCredential())!;
  f.records.set(
    'vault',
    CryptoJS.AES.encrypt(
      JSON.stringify({ mnemonic }),
      Buffer.from(old.key).toString('hex')
    ).toString()
  );
  await ring.lockWallet();
  const before = JSON.stringify([...f.records]);
  f.readCredential.mockResolvedValueOnce({
    pairFingerprint: (await f.readPair())!.pairFingerprint,
    key: old.key,
  });
  await expect(controls.resume(current)).rejects.toThrow(
    'Invalid encrypted vault format'
  );
  expect(old.key).toEqual(new Uint8Array(32));
  await expect(controls.issue(password, current)).rejects.toThrow(
    'Invalid encrypted vault format'
  );
  expect(f.writeCredential).toHaveBeenCalledTimes(1);
  expect(ring.isUnlocked()).toBe(false);
  expect(JSON.stringify([...f.records])).toBe(before);
  await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
  await expect(ring.getSeed(password)).resolves.toBe(mnemonic);
});

it.each(['tag', 'shape', 'legacy keys'])(
  'refuses damaged or unsupported %s without altering the stored vault',
  async (kind) => {
    const f = fixture();
    const { ring, controls } = await f.create();
    await expect(controls.issue(password, current)).resolves.toBe(true);
    const old = (await f.readCredential())!;
    await ring.lockWallet();
    const envelope = JSON.parse(f.records.get('vault'));
    if (kind === 'legacy keys') {
      f.records.set('vault-keys', {
        ...f.records.get('vault-keys'),
        keyDerivation: 'pbkdf2-sha512-20000',
      });
    } else {
      if (kind === 'shape') envelope.iv += '00';
      else
        envelope.ct =
          (envelope.ct[0] === '0' ? '1' : '0') + envelope.ct.slice(1);
      f.records.set('vault', JSON.stringify(envelope));
    }
    const before = JSON.stringify([...f.records]);
    f.readCredential.mockResolvedValueOnce({
      pairFingerprint: (await f.readPair())!.pairFingerprint,
      key: old.key,
    });
    if (kind === 'tag') {
      await expect(controls.resume(current)).resolves.toBe(false);
      await expect(controls.issue(password, current)).resolves.toBe(false);
    } else {
      const error =
        kind === 'shape'
          ? 'Invalid encrypted vault format'
          : 'Invalid device unlock vault pair';
      await expect(controls.resume(current)).rejects.toThrow(error);
      await expect(controls.issue(password, current)).rejects.toThrow(error);
    }
    expect(ring.isUnlocked()).toBe(false);
    expect(f.writeCredential).toHaveBeenCalledTimes(1);
    expect(JSON.stringify([...f.records])).toBe(before);
  }
);
