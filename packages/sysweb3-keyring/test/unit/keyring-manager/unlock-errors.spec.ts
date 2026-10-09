import { webcrypto } from 'crypto';
import CryptoJS from 'crypto-js';

import type { KeyringManager } from '../../../src';

const key = '11'.repeat(32);
const wrongKey = '22'.repeat(32);
const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

describe('KeyringManager unlock error classification with real WebCrypto', () => {
  const values = new Map<string, any>();
  const storage = {
    async get(name: string) {
      return values.get(name);
    },
    async set(name: string, value: any) {
      values.set(name, value);
    },
  };
  let Keyring: typeof KeyringManager;
  let getDecryptedVault: typeof import('../../../src/storage').getDecryptedVault;
  let setEncryptedVault: typeof import('../../../src/storage').setEncryptedVault;
  let keyring: KeyringManager;
  let internals: any;
  let cryptoDescriptor: PropertyDescriptor | undefined;
  let locationDescriptor: PropertyDescriptor | undefined;

  beforeAll(() => {
    // The shared test setup creates a new storage wrapper per call. Use one
    // explicit client here so failures exercise both the manager and storage.
    jest.resetModules();
    locationDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      'location'
    );
    Object.defineProperty(globalThis, 'location', {
      configurable: true,
      value: { href: 'https://wallet.test/' },
    });
    jest.doMock('@sidhujag/sysweb3-core', () => ({
      sysweb3Di: { getStateStorageDb: () => storage },
    }));
    jest.isolateModules(() => {
      Keyring = require('../../../src').KeyringManager;
      ({
        getDecryptedVault,
        setEncryptedVault,
      } = require('../../../src/storage'));
    });
  });

  afterAll(() => {
    if (locationDescriptor) {
      Object.defineProperty(globalThis, 'location', locationDescriptor);
    } else {
      delete (globalThis as any).location;
    }
  });

  beforeEach(async () => {
    values.clear();
    cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: webcrypto,
    });
    jest.spyOn(console, 'log').mockImplementation(() => undefined);
    jest.spyOn(console, 'error').mockImplementation(() => undefined);

    await storage.set('vault-keys', { salt: '33'.repeat(16) });
    await setEncryptedVault({ mnemonic }, key);
    keyring = new Keyring();
    internals = keyring as any;
    // Keep the KDF deterministic and fast; vault encryption and authentication
    // use Node's real WebCrypto rather than the global test crypto mock.
    jest
      .spyOn(internals, 'encryptSHA512Async')
      .mockImplementation(async (password) => {
        return password === 'correct' ? key : wrongKey;
      });
    keyring.setVaultStateGetter(() => ({
      activeAccount: { id: 0, type: 'HDAccount' },
      activeNetwork: { kind: 'ethereum' },
      accounts: { HDAccount: { 0: {} } },
    }));
  });

  afterEach(async () => {
    await keyring.lockWallet();
    jest.restoreAllMocks();
    if (cryptoDescriptor) {
      Object.defineProperty(globalThis, 'crypto', cryptoDescriptor);
    }
  });

  it('unlocks a healthy AES-GCM vault', async () => {
    await expect(keyring.unlock('correct')).resolves.toEqual({
      canLogin: true,
    });
    expect(keyring.isUnlocked()).toBe(true);
  });

  it('returns false for an actual AES-GCM password authentication failure', async () => {
    await expect(keyring.unlock('wrong')).resolves.toEqual({ canLogin: false });
    expect(keyring.isUnlocked()).toBe(false);
  });

  it('preserves legacy CBC password rejection and successful unlock', async () => {
    await storage.set(
      'vault',
      CryptoJS.AES.encrypt(JSON.stringify({ mnemonic }), key).toString()
    );
    await expect(keyring.unlock('wrong')).resolves.toEqual({ canLogin: false });
    expect(keyring.isUnlocked()).toBe(false);
    await expect(keyring.unlock('correct')).resolves.toEqual({
      canLogin: true,
    });
  });

  it('propagates a temporary storage failure and allows a later retry', async () => {
    const error = new Error('storage temporarily unavailable');
    jest.spyOn(storage, 'get').mockRejectedValueOnce(error);
    await expect(keyring.unlock('correct')).rejects.toBe(error);
    await expect(keyring.unlock('correct')).resolves.toEqual({
      canLogin: true,
    });
  });

  it('propagates missing vault keys', async () => {
    await storage.set('vault-keys', null);
    await expect(keyring.unlock('correct')).rejects.toThrow(
      'Vault keys not found'
    );
  });

  it('propagates a missing encrypted vault', async () => {
    await storage.set('vault', null);
    await expect(keyring.unlock('correct')).rejects.toThrow('Vault not found');
  });

  it('propagates a KDF failure', async () => {
    const error = new Error('KDF temporarily unavailable');
    internals.encryptSHA512Async.mockRejectedValueOnce(error);
    await expect(keyring.unlock('correct')).rejects.toBe(error);
  });

  it('cleans up if the vault read after authentication fails', async () => {
    const error = new Error('vault read interrupted after authentication');
    const originalGet = storage.get;
    let vaultReads = 0;
    jest.spyOn(storage, 'get').mockImplementation(async (name) => {
      if (name === 'vault' && ++vaultReads === 2) throw error;
      return originalGet(name);
    });
    const cleanup = jest.spyOn(keyring, 'lockWallet');
    await expect(keyring.unlock('correct')).rejects.toBe(error);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(keyring.isUnlocked()).toBe(false);
  });

  it('clears restored secret buffers if account state fails after authentication', async () => {
    const error = new Error('account state not ready');
    let passwordBuffer: any;
    let mnemonicBuffer: any;
    keyring.setVaultStateGetter(() => {
      passwordBuffer = internals.sessionPassword;
      mnemonicBuffer = internals.sessionMnemonic;
      throw error;
    });

    await expect(keyring.unlock('correct')).rejects.toBe(error);
    expect(passwordBuffer.isCleared()).toBe(true);
    expect(mnemonicBuffer.isCleared()).toBe(true);
    expect(internals.sessionPassword).toBeNull();
    expect(internals.sessionMnemonic).toBeNull();
    expect(keyring.isUnlocked()).toBe(false);
  });

  it('propagates a non-authentication WebCrypto decrypt failure', async () => {
    const error = new DOMException(
      'crypto service unavailable',
      'InvalidStateError'
    );
    jest.spyOn(webcrypto.subtle, 'decrypt').mockRejectedValueOnce(error);
    await expect(keyring.unlock('correct')).rejects.toBe(error);
  });

  it('propagates key import OperationError without calling it a bad password', async () => {
    const error = new DOMException('key import unavailable', 'OperationError');
    jest.spyOn(webcrypto.subtle, 'importKey').mockRejectedValueOnce(error);
    await expect(keyring.unlock('correct')).rejects.toBe(error);
  });

  it.each([
    ['iv', '11'],
    ['ct', '11'],
  ])(
    'rejects a malformed AES-GCM %s before authentication',
    async (field, value) => {
      const envelope = JSON.parse(await storage.get('vault'));
      envelope[field] = value;
      await storage.set('vault', JSON.stringify(envelope));
      await expect(keyring.unlock('correct')).rejects.toThrow(
        'Invalid encrypted vault format'
      );
    }
  );

  it('keeps authenticated AES-GCM plaintext parse failures operational', async () => {
    const iv = new Uint8Array(12);
    const cryptoKey = await webcrypto.subtle.importKey(
      'raw',
      Buffer.from(key, 'hex'),
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );
    const ciphertext = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      cryptoKey,
      new TextEncoder().encode('invalid JSON')
    );
    await storage.set(
      'vault',
      JSON.stringify({
        v: 4,
        alg: 'A256GCM',
        iv: Buffer.from(iv).toString('hex'),
        ct: Buffer.from(ciphertext).toString('hex'),
      })
    );
    await expect(getDecryptedVault(key)).rejects.toBeInstanceOf(SyntaxError);
    await expect(keyring.unlock('correct')).rejects.toBeInstanceOf(SyntaxError);
  });

  it('propagates a migration write failure after successful legacy authentication', async () => {
    await storage.set('vault-keys', {
      salt: '33'.repeat(16),
      currentSessionSalt: '44'.repeat(16),
    });
    await storage.set(
      'vault',
      CryptoJS.AES.encrypt(JSON.stringify({ mnemonic }), 'correct').toString()
    );
    const error = new Error('migration storage write unavailable');
    const originalSet = storage.set;
    jest.spyOn(storage, 'set').mockImplementation(async (name, value) => {
      if (name === 'vault-keys') throw error;
      return originalSet(name, value);
    });
    const cleanup = jest.spyOn(keyring, 'lockWallet');
    await expect(keyring.unlock('correct')).rejects.toBe(error);
    expect(cleanup).toHaveBeenCalledTimes(1);
    expect(keyring.isUnlocked()).toBe(false);
  });
});
