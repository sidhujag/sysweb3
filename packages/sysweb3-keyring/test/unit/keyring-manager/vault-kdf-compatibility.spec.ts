import { pbkdf2Sync, webcrypto } from 'crypto';
import CryptoJS from 'crypto-js';

const password = 'synthetic compatibility password';
const salt = '33'.repeat(16);
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const accountSecret = '0x' + '42'.repeat(32);
const legacyProfile = 'pbkdf2-sha512-20000';
const legacyKey = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
  keySize: 8,
  iterations: 20_000,
  hasher: CryptoJS.algo.SHA512,
}).toString();

const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

describe('production KDF compatibility through the real core adapter', () => {
  const data: Record<string, any> = {};
  let Keyring: any;
  let db: any;
  let setEncryptedVault: any;
  let getDecryptedVault: any;
  let ring: any;
  let client: any;
  let originalCrypto: PropertyDescriptor | undefined;
  let originalNodeEnv: string | undefined;
  let originalIterations: string | undefined;
  let originalLocation: PropertyDescriptor | undefined;

  const installLegacy = () => {
    data['sysweb3-vault-keys'] = { salt };
    data['sysweb3-vault'] = CryptoJS.AES.encrypt(
      JSON.stringify({ mnemonic }),
      legacyKey
    ).toString();
  };
  const createRing = () => {
    const result = new Keyring();
    result.setVaultStateGetter(() => ({
      activeAccount: { id: 0, type: 'HDAccount' },
      activeNetwork: { kind: 'ethereum' },
      accounts: {
        HDAccount: {
          0: {
            xprv: CryptoJS.AES.encrypt(accountSecret, legacyKey).toString(),
          },
        },
      },
    }));
    return result;
  };

  beforeAll(() => {
    originalLocation = Object.getOwnPropertyDescriptor(globalThis, 'location');
    Object.defineProperty(globalThis, 'location', {
      configurable: true,
      value: { href: 'https://wallet.test/' },
    });
    jest.resetModules();
    jest.doMock('@sidhujag/sysweb3-core', () =>
      jest.requireActual('@sidhujag/sysweb3-core')
    );
    jest.isolateModules(() => {
      Keyring = require('../../../src').KeyringManager;
      db = require('@sidhujag/sysweb3-core').sysweb3Di.getStateStorageDb();
      ({
        setEncryptedVault,
        getDecryptedVault,
      } = require('../../../src/storage'));
    });
  });
  beforeEach(() => {
    Object.keys(data).forEach((key) => delete data[key]);
    originalCrypto = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: webcrypto,
    });
    originalNodeEnv = process.env.NODE_ENV;
    originalIterations = process.env.SYSWEB3_PBKDF2_ENC_ITERS;
    process.env.NODE_ENV = 'production';
    delete process.env.SYSWEB3_PBKDF2_ENC_ITERS;
    client = {
      get: jest.fn(async (keys: string[]) =>
        Object.fromEntries(keys.map((key) => [key, data[key]]))
      ),
      set: jest.fn(async (value: any) => {
        Object.assign(data, value);
      }),
      remove: jest.fn(async (key: string) => {
        delete data[key];
      }),
    };
    db.setClient(client);
    ring = createRing();
    client.set.mockClear();
    delete data['sysweb3-utf8Error'];
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
  });
  afterEach(async () => {
    await ring.lockWallet();
    jest.restoreAllMocks();
    db.setClient();
    if (originalCrypto)
      Object.defineProperty(globalThis, 'crypto', originalCrypto);
    if (originalNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalNodeEnv;
    if (originalIterations === undefined)
      delete process.env.SYSWEB3_PBKDF2_ENC_ITERS;
    else process.env.SYSWEB3_PBKDF2_ENC_ITERS = originalIterations;
  });

  afterAll(() => {
    if (originalLocation)
      Object.defineProperty(globalThis, 'location', originalLocation);
    else delete (globalThis as any).location;
  });

  it.each([false, true])(
    'ignores rejected best-effort diagnostics (synchronous: %s)',
    async (synchronous) => {
      installLegacy();
      const unhandled = jest.fn();
      process.on('unhandledRejection', unhandled);
      client.set.mockImplementation((value: any) => {
        if ('sysweb3-utf8Error' in value) {
          const error = new Error('diagnostic storage offline');
          if (synchronous) throw error;
          return Promise.reject(error);
        }
        Object.assign(data, value);
        return Promise.resolve();
      });
      try {
        ring = createRing();
        ring.validateAndHandleErrorByMessage('Malformed UTF-8 data');
        await expect(ring.unlock(password)).resolves.toEqual({
          canLogin: true,
        });
        await new Promise<void>((resolve) => setImmediate(resolve));
        expect(unhandled).not.toHaveBeenCalled();
      } finally {
        process.off('unhandledRejection', unhandled);
      }
    }
  );

  it('uses 900k PBKDF2/SHA-512 for a new wallet and stores only authenticated encryption', async () => {
    await ring.initializeSession(mnemonic, password);
    const freshSalt = data['sysweb3-vault-keys'].salt;
    const expected = pbkdf2Sync(
      password,
      Buffer.from(freshSalt, 'hex'),
      900_000,
      32,
      'sha512'
    ).toString('hex');
    expect(ring.getSessionPasswordString()).toBe(expected);
    expect(expected).not.toBe(legacyKey);
    expect(JSON.parse(data['sysweb3-vault']).alg).toBe('A256GCM');
    expect(await getDecryptedVault(expected)).toEqual({ mnemonic });
  });

  it('publishes a fresh salt and ciphertext together only after the native write succeeds', async () => {
    const entered = deferred();
    const release = deferred();
    client.set.mockImplementation(async (value: any) => {
      entered.resolve();
      await release.promise;
      Object.assign(data, value);
    });
    const creation = ring.initializeSession(mnemonic, password);
    await entered.promise;
    expect(data).toEqual({});
    expect(client.set).toHaveBeenCalledTimes(1);
    expect(client.set.mock.calls[0][0]).toEqual({
      'sysweb3-vault-keys': { salt: expect.stringMatching(/^[a-f0-9]{32}$/) },
      'sysweb3-vault': expect.any(String),
    });
    release.resolve();
    await creation;
    expect(JSON.parse(data['sysweb3-vault']).alg).toBe('A256GCM');
    await ring.lockWallet();
    ring = createRing();
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    expect(await ring.getSeed(password)).toBe(mnemonic);
  });

  it('leaves no fresh-wallet metadata after a rejected native write and permits a safe retry', async () => {
    const error = new Error('native batch quota failure');
    client.set.mockImplementationOnce(async (value: any) => {
      // Before the fix, the first standalone salt write succeeded, then
      // ciphertext failed. Reject the vault-containing call in both versions.
      if ('sysweb3-vault' in value) throw error;
      Object.assign(data, value);
    });
    client.set.mockImplementationOnce(async () => {
      throw error;
    });
    await expect(ring.initializeSession(mnemonic, password)).rejects.toBe(
      error
    );
    expect(data).toEqual({});
    client.set.mockReset().mockImplementation(async (value: any) => {
      Object.assign(data, value);
    });
    await expect(
      ring.initializeSession(mnemonic, password)
    ).resolves.toBeUndefined();
    expect(await ring.getSeed(password)).toBe(mnemonic);
  });

  it('does not publish fresh metadata when encryption fails before the batch write', async () => {
    const error = new Error('WebCrypto encryption failed');
    jest.spyOn(webcrypto.subtle, 'encrypt').mockRejectedValueOnce(error);
    await expect(ring.initializeSession(mnemonic, password)).rejects.toBe(
      error
    );
    expect(data).toEqual({});
    expect(client.set).not.toHaveBeenCalled();
  });

  it.each([
    {
      'sysweb3-vault': 'pre-existing ciphertext',
      'sysweb3-vault-keys': { salt },
    },
    { 'sysweb3-vault': 'pre-existing ciphertext' },
    { 'sysweb3-vault-keys': { salt } },
    { 'sysweb3-vault': '' },
    { 'sysweb3-vault-keys': false },
  ])(
    'does not replace existing or incomplete wallet storage %p',
    async (stored) => {
      Object.assign(data, stored);
      const before = { ...data };
      const derive = jest.spyOn(webcrypto.subtle, 'deriveBits');
      const encrypt = jest.spyOn(webcrypto.subtle, 'encrypt');
      await expect(ring.initializeSession(mnemonic, password)).rejects.toThrow(
        'Cannot initialize a new vault over existing wallet storage'
      );
      expect(data).toEqual(before);
      expect(derive).not.toHaveBeenCalled();
      expect(encrypt).not.toHaveBeenCalled();
      expect(client.set).not.toHaveBeenCalled();
      expect(ring.isUnlocked()).toBe(false);
    }
  );

  it('rechecks malformed existing records inside the fresh-vault mutex', async () => {
    data['sysweb3-vault'] = false;
    await expect(
      setEncryptedVault({ mnemonic }, '42'.repeat(32), { salt })
    ).rejects.toThrow(
      'Cannot initialize a new vault over existing wallet storage'
    );
    expect(data).toEqual({ 'sysweb3-vault': false });
    expect(client.set).not.toHaveBeenCalled();
  });

  it('allows only one concurrent initializer to publish a fresh wallet', async () => {
    const entered = deferred();
    const release = deferred();
    const secondDerived = deferred();
    const other = createRing();
    const derive = other.deriveStoredSessionKey.bind(other);
    jest
      .spyOn(other, 'deriveStoredSessionKey')
      .mockImplementation(async (...args: any[]) => {
        const key = await derive(...args);
        secondDerived.resolve();
        return key;
      });
    client.set.mockImplementation(async (value: any) => {
      if (!('sysweb3-vault' in value)) {
        Object.assign(data, value);
        return;
      }
      entered.resolve();
      await release.promise;
      Object.assign(data, value);
    });
    try {
      const first = ring.initializeSession(mnemonic, password);
      await entered.promise;
      const second = other.initializeSession(
        'legal winner thank year wave sausage worth useful legal winner thank yellow',
        'different fixture password'
      );
      const rejected = expect(second).rejects.toThrow(
        'Cannot initialize a new vault over existing wallet storage'
      );
      await secondDerived.promise;
      release.resolve();
      await first;
      await rejected;
      expect(
        client.set.mock.calls.filter(([value]) => 'sysweb3-vault' in value)
      ).toHaveLength(1);
      expect(await ring.getSeed(password)).toBe(mnemonic);
      expect(other.isUnlocked()).toBe(false);
    } finally {
      release.resolve();
      await other.destroy();
    }
  });

  it('keeps matching live-session initialization read-only', async () => {
    await ring.initializeSession(mnemonic, password);
    const before = { ...data };
    client.set.mockClear();
    await expect(
      ring.initializeSession(mnemonic, password)
    ).resolves.toBeUndefined();
    expect(data).toEqual(before);
    expect(client.set).not.toHaveBeenCalled();
  });

  it('rejects a fresh creation on a sequential-only adapter before any write', async () => {
    const sequential = {
      getItem: jest.fn(() => null),
      setItem: jest.fn(),
      removeItem: jest.fn(),
    };
    db.setClient(sequential);
    await expect(ring.initializeSession(mnemonic, password)).rejects.toThrow(
      'Storage adapter does not support atomic batch writes'
    );
    expect(sequential.setItem).not.toHaveBeenCalled();
  });

  it('leaves a complete recoverable vault if the batch commits but acknowledgement is lost', async () => {
    const error = new Error('write acknowledgement lost');
    client.set.mockImplementationOnce(async (value: any) => {
      Object.assign(data, value);
      throw error;
    });
    await expect(ring.initializeSession(mnemonic, password)).rejects.toBe(
      error
    );
    expect(data['sysweb3-vault-keys']).toEqual({ salt: expect.any(String) });
    expect(JSON.parse(data['sysweb3-vault']).alg).toBe('A256GCM');
    ring = createRing();
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    expect(await ring.getSeed(password)).toBe(mnemonic);
  });

  it('retains legacy account access after WebCrypto appears and after restarting', async () => {
    installLegacy();
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    expect(data['sysweb3-vault-keys']).toEqual({
      salt,
      keyDerivation: legacyProfile,
    });
    expect(JSON.parse(data['sysweb3-vault']).alg).toBe('A256GCM');
    expect(await ring.getSeed(password)).toBe(mnemonic);
    expect(await ring.getPrivateKeyByAccountId(0, 'HDAccount', password)).toBe(
      accountSecret
    );
    await ring.lockWallet();
    ring = createRing();
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    expect(await ring.getSeed(password)).toBe(mnemonic);
    expect(await ring.getPrivateKeyByAccountId(0, 'HDAccount', password)).toBe(
      accountSecret
    );
    await expect(ring.unlock('wrong password')).resolves.toEqual({
      canLogin: false,
    });
  });

  it('rejects initialization over a persisted compatibility wallet and restores it through unlock', async () => {
    installLegacy();
    await ring.unlock(password);
    await ring.lockWallet();
    ring = createRing();
    const before = { ...data };
    client.set.mockClear();
    await expect(ring.initializeSession(mnemonic, password)).rejects.toThrow(
      'Cannot initialize a new vault over existing wallet storage'
    );
    expect(data).toEqual(before);
    expect(client.set).not.toHaveBeenCalled();
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
    expect(await ring.getPrivateKeyByAccountId(0, 'HDAccount', password)).toBe(
      accountSecret
    );
    expect(await ring.getSeed(password)).toBe(mnemonic);
  });

  it('requires WebCrypto without changing an unmarked legacy vault, then recovers when restored', async () => {
    installLegacy();
    const before = { ...data };
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) },
    });
    await expect(ring.unlock(password)).rejects.toThrow(
      'WebCrypto is required'
    );
    expect(data).toEqual(before);
    expect(client.set).not.toHaveBeenCalled();
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: webcrypto,
    });
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
  });

  it('never creates a CBC vault or metadata when WebCrypto is unavailable', async () => {
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: {},
    });
    await expect(ring.initializeSession(mnemonic, password)).rejects.toThrow(
      'WebCrypto is required'
    );
    await expect(setEncryptedVault({ mnemonic }, legacyKey)).rejects.toThrow(
      'WebCrypto is required'
    );
    expect(client.set).not.toHaveBeenCalled();
    expect(data).toEqual({});
  });

  it('does not let metadata specify arbitrary KDF parameters', async () => {
    installLegacy();
    data['sysweb3-vault-keys'].keyDerivation = { iterations: 1 };
    const derive = jest.spyOn(webcrypto.subtle, 'deriveBits');
    await expect(ring.unlock(password)).rejects.toThrow(
      'Unsupported vault key derivation profile'
    );
    expect(derive).not.toHaveBeenCalled();
    expect(client.set).not.toHaveBeenCalled();
  });

  it('does not try the legacy KDF for a corrupted modern GCM vault', async () => {
    data['sysweb3-vault-keys'] = { salt };
    await setEncryptedVault({ mnemonic }, legacyKey);
    const derive = jest.spyOn(webcrypto.subtle, 'deriveBits');
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: false });
    expect(derive).toHaveBeenCalledTimes(1);
  });

  it.each(['profile', 'ciphertext'])(
    'keeps legacy recovery possible after a rejected %s write',
    async (failure) => {
      installLegacy();
      const originalVault = data['sysweb3-vault'];
      const error = new Error('asynchronous storage rejection');
      const save = client.set.getMockImplementation();
      client.set.mockImplementationOnce(async (value: any) => {
        if (failure === 'profile') throw error;
        return save(value);
      });
      if (failure === 'ciphertext') client.set.mockRejectedValueOnce(error);
      await expect(ring.unlock(password)).rejects.toBe(error);
      expect(data['sysweb3-vault']).toBe(originalVault);
      expect(data['sysweb3-vault-keys']).toEqual(
        failure === 'profile'
          ? { salt }
          : { salt, keyDerivation: legacyProfile }
      );
      await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
      expect(JSON.parse(data['sysweb3-vault']).alg).toBe('A256GCM');
      expect(
        await ring.getPrivateKeyByAccountId(0, 'HDAccount', password)
      ).toBe(accountSecret);
    }
  );

  it('awaits the actual Chrome vault write before removing the legacy session salt', async () => {
    const oldSalt = '44'.repeat(16);
    const oldKey = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(oldSalt), {
      keySize: 8,
      iterations: 20_000,
      hasher: CryptoJS.algo.SHA512,
    }).toString();
    const encryptedMnemonic = CryptoJS.AES.encrypt(mnemonic, oldKey).toString();
    data['sysweb3-vault-keys'] = { salt, currentSessionSalt: oldSalt };
    data['sysweb3-vault'] = CryptoJS.AES.encrypt(
      JSON.stringify({ mnemonic: encryptedMnemonic }),
      password
    ).toString();
    const entered = deferred();
    const release = deferred();
    client.set.mockImplementation(async (value: any) => {
      if ('sysweb3-vault' in value) {
        entered.resolve();
        await release.promise;
      }
      Object.assign(data, value);
    });
    let settled = false;
    const unlock = ring.unlock(password).finally(() => {
      settled = true;
    });
    await entered.promise;
    expect(data['sysweb3-vault-keys']).toEqual({
      salt,
      currentSessionSalt: oldSalt,
    });
    expect(settled).toBe(false);
    release.resolve();
    await expect(unlock).resolves.toEqual({ canLogin: true });
    expect(data['sysweb3-vault-keys']).toEqual({ salt });
  });

  it('preserves old migration records when the real adapter rejects the vault write', async () => {
    data['sysweb3-vault-keys'] = { salt, currentSessionSalt: '44'.repeat(16) };
    data['sysweb3-vault'] = CryptoJS.AES.encrypt(
      JSON.stringify({ mnemonic }),
      password
    ).toString();
    const before = { ...data };
    const error = new Error('Chrome quota write failure');
    client.set.mockRejectedValueOnce(error);
    await expect(ring.unlock(password)).rejects.toBe(error);
    expect(data).toEqual(before);
    await expect(ring.unlock(password)).resolves.toEqual({ canLogin: true });
  });
});
