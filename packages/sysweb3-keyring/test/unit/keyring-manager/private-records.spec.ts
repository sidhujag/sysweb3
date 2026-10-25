import { createDecipheriv, hkdfSync, webcrypto } from 'crypto';
import CryptoJS from 'crypto-js';

import { HardwareWalletManager } from '../../../src/hardware-wallet-manager';
import { KeyringManager } from '../../../src/keyring-manager';
import {
  IEncryptedPrivateRecord,
  MAX_PRIVATE_RECORD_BYTES,
} from '../../../src/private-records';

const ROOT = 'synthetic root secret for private record tests';
const DOMAIN = 'org.syscoin.pali.privacy.notes.v1';
const RECORD_ID = '4fddac53-c01d-4c8e-8b86-5a37f5430cf1';
const TEXT = 'synthetic private note and encrypted metadata';
const bytes = () => new TextEncoder().encode(TEXT);

class TestBuffer {
  private cleared = false;
  constructor(private value: string) {}
  toString() {
    if (this.cleared) throw new Error('cleared test buffer');
    return this.value;
  }
  isCleared() {
    return this.cleared;
  }
  clear() {
    this.value = '';
    this.cleared = true;
  }
}

function installSession(
  manager: KeyringManager,
  root = ROOT,
  password = 'synthetic session wrapping key'
) {
  manager.receiveSessionOwnership(
    new TestBuffer(password) as any,
    new TestBuffer(CryptoJS.AES.encrypt(root, password).toString()) as any
  );
}

function fixture(root = ROOT, password?: string) {
  // The configured test storage is in memory; no initialize/unlock/storage API
  // is used to create these synthetic encrypted session buffers.
  const manager = new KeyringManager(new HardwareWalletManager());
  (manager as any).ledgerSigner = undefined;
  (manager as any).trezorSigner = undefined;
  installSession(manager, root, password);
  return manager;
}

const seal = (manager: KeyringManager) =>
  manager.encryptPrivateRecord({
    domain: DOMAIN,
    recordId: RECORD_ID,
    plaintext: bytes(),
  });
const open = (manager: KeyringManager, envelope: IEncryptedPrivateRecord) =>
  manager.decryptPrivateRecord({
    domain: DOMAIN,
    recordId: RECORD_ID,
    envelope,
  });

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function pauseCrypto(method: keyof SubtleCrypto) {
  const started = deferred<void>();
  const release = deferred<void>();
  let captured: unknown;
  let input: unknown;
  const subtle = new Proxy(webcrypto.subtle, {
    get(target, key) {
      const original = Reflect.get(target, key);
      if (key !== method) {
        return typeof original === 'function'
          ? original.bind(target)
          : original;
      }
      return async (...args: unknown[]) => {
        input = args[2];
        captured = await original.apply(target, args);
        started.resolve();
        await release.promise;
        return captured;
      };
    },
  });
  global.crypto = {
    subtle,
    getRandomValues: webcrypto.getRandomValues.bind(webcrypto),
  } as any;
  return {
    started: started.promise,
    release: () => release.resolve(),
    output: () => captured,
    input: () => input,
  };
}

beforeEach(() => {
  global.crypto = webcrypto as any;
  // No device monitoring is needed for this synthetic session-only fixture.
  jest
    .spyOn(HardwareWalletManager.prototype as any, 'startStatusMonitoring')
    .mockImplementation(() => undefined);
});
afterEach(() => {
  global.crypto = webcrypto as any;
  jest.restoreAllMocks();
});

describe('private record custody', () => {
  it('matches independent Node HKDF and AES-GCM primitives', async () => {
    const manager = fixture();
    const envelope = await seal(manager);
    const namespace = 'sysweb3/private-record/v1';
    expect(await manager.getPrivateRecordProfileId()).toBe(
      '0x0869e9262d7bd77eec1b7f493e8059a601fbbe70807b6c0742836eb3e1da7224'
    );
    const key = Buffer.from(
      hkdfSync(
        'sha256',
        Buffer.from(ROOT.normalize('NFKD')),
        Buffer.from(namespace),
        Buffer.from(JSON.stringify([namespace, 'encryption-key', DOMAIN])),
        32
      )
    );
    const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(envelope.nonce, 'base64')
    );
    decipher.setAAD(
      Buffer.from(
        JSON.stringify([namespace, 1, DOMAIN, RECORD_ID, envelope.profileId])
      )
    );
    decipher.setAuthTag(ciphertext.subarray(-16));
    expect(
      Buffer.concat([
        decipher.update(ciphertext.subarray(0, -16)),
        decipher.final(),
      ])
    ).toEqual(Buffer.from(bytes()));
    key.fill(0);
  });

  it('uses stable root identity across account/network and password changes', async () => {
    const manager = fixture();
    const getter = jest.fn(() => ({
      activeAccount: { id: 1, type: 'HDAccount' },
      activeNetwork: { chainId: 1, slip44: 60 },
    }));
    manager.setVaultStateGetter(getter);
    const profile = await manager.getPrivateRecordProfileId();
    const envelope = await seal(manager);
    getter.mockReturnValue({
      activeAccount: { id: 2, type: 'Imported' },
      activeNetwork: { chainId: 57, slip44: 57 },
    });
    expect(await manager.getPrivateRecordProfileId()).toBe(profile);
    installSession(manager, ROOT, 'a changed session password');
    expect(await manager.getPrivateRecordProfileId()).toBe(profile);
    expect(await open(manager, envelope)).toEqual(bytes());
    expect(
      await fixture(ROOT, 'another password').getPrivateRecordProfileId()
    ).toBe(profile);
    expect(getter).not.toHaveBeenCalled();
  });

  it('uses a fresh 96-bit nonce and returns only the public envelope', async () => {
    const manager = fixture();
    const first = await seal(manager);
    const second = await seal(manager);
    expect(first.profileId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(Buffer.from(first.nonce, 'base64')).toHaveLength(12);
    expect(Buffer.from(first.ciphertext, 'base64')).toHaveLength(
      bytes().length + 16
    );
    expect(Object.keys(first).sort()).toEqual([
      'ciphertext',
      'domain',
      'nonce',
      'profileId',
      'recordId',
      'version',
    ]);
    expect(await open(manager, first)).toEqual(bytes());
    expect(await open(manager, second)).toEqual(bytes());
  });

  it('never reads or writes wallet storage while sealing or opening a record', async () => {
    const manager = fixture();
    const storage = (manager as any).storage;
    const getSeed = jest.spyOn(manager, 'getSeed');
    jest.clearAllMocks();
    const envelope = await seal(manager);
    await manager.getPrivateRecordProfileId();
    await open(manager, envelope);
    expect(getSeed).not.toHaveBeenCalled();
    for (const name of [
      'get',
      'set',
      'setMany',
      'createManyIfAbsent',
      'deleteItem',
    ]) {
      if (storage[name]) expect(storage[name]).not.toHaveBeenCalled();
    }
  });

  it('copies plaintext and context before asynchronous work begins', async () => {
    const manager = fixture();
    const pause = pauseCrypto('importKey');
    const params = { domain: DOMAIN, recordId: RECORD_ID, plaintext: bytes() };
    const pending = manager.encryptPrivateRecord(params);
    await pause.started;
    params.plaintext.fill(0);
    params.domain = 'changed.domain';
    params.recordId = 'changed-id';
    pause.release();
    const envelope = await pending;
    global.crypto = webcrypto as any;
    expect(envelope.domain).toBe(DOMAIN);
    expect(envelope.recordId).toBe(RECORD_ID);
    expect(await open(manager, envelope)).toEqual(bytes());
  });

  it('copies the encrypted envelope before asynchronous decryption', async () => {
    const manager = fixture();
    const envelope = await seal(manager);
    const pause = pauseCrypto('importKey');
    const pending = open(manager, envelope);
    await pause.started;
    envelope.domain = 'changed.domain';
    envelope.nonce = '';
    envelope.ciphertext = '';
    pause.release();
    expect(await pending).toEqual(bytes());
  });

  it.each(['ciphertext', 'nonce'] as const)(
    'rejects tampered %s',
    async (field) => {
      const manager = fixture();
      const envelope = await seal(manager);
      const raw = Buffer.from(envelope[field], 'base64');
      raw[0] ^= 1;
      envelope[field] = raw.toString('base64');
      await expect(open(manager, envelope)).rejects.toThrow(
        'authentication failed'
      );
    }
  );

  it('authenticates the version, domain, record ID and profile', async () => {
    const manager = fixture();
    const envelope = await seal(manager);
    await expect(
      open(manager, { ...envelope, version: 2 } as any)
    ).rejects.toThrow();
    await expect(
      manager.decryptPrivateRecord({
        domain: 'another.domain',
        recordId: RECORD_ID,
        envelope,
      })
    ).rejects.toThrow();
    await expect(
      manager.decryptPrivateRecord({
        domain: 'another.domain',
        recordId: RECORD_ID,
        envelope: { ...envelope, domain: 'another.domain' },
      })
    ).rejects.toThrow('authentication failed');
    await expect(
      manager.decryptPrivateRecord({
        domain: DOMAIN,
        recordId: 'another-id',
        envelope: { ...envelope, recordId: 'another-id' },
      })
    ).rejects.toThrow('authentication failed');
    await expect(
      open(manager, { ...envelope, profileId: `0x${'00'.repeat(32)}` })
    ).rejects.toThrow('profile mismatch');
    await expect(
      open(fixture('different synthetic root'), envelope)
    ).rejects.toThrow('profile mismatch');
  });

  it('accepts empty and maximum-size records but rejects oversized input', async () => {
    const manager = fixture();
    for (const plaintext of [
      new Uint8Array(),
      new Uint8Array(MAX_PRIVATE_RECORD_BYTES).fill(5),
    ]) {
      const envelope = await manager.encryptPrivateRecord({
        domain: DOMAIN,
        recordId: RECORD_ID,
        plaintext,
      });
      expect(await open(manager, envelope)).toEqual(plaintext);
    }
    await expect(
      manager.encryptPrivateRecord({
        domain: DOMAIN,
        recordId: RECORD_ID,
        plaintext: new Uint8Array(MAX_PRIVATE_RECORD_BYTES + 1),
      })
    ).rejects.toThrow('size');
  });

  it.each([
    '',
    'x'.repeat(129),
    'space domain',
    'new' + String.fromCharCode(10) + 'line',
    'trailing' + String.fromCharCode(10),
    'trailing' + String.fromCharCode(13),
    String.fromCharCode(0xd800),
    'é',
  ])('rejects invalid context %j', async (value) => {
    const manager = fixture();
    await expect(
      manager.encryptPrivateRecord({
        domain: value,
        recordId: RECORD_ID,
        plaintext: bytes(),
      })
    ).rejects.toThrow('context');
    await expect(
      manager.encryptPrivateRecord({
        domain: DOMAIN,
        recordId: value,
        plaintext: bytes(),
      })
    ).rejects.toThrow('context');
  });

  it('rejects oversized or noncanonical encoded envelopes before decrypting', async () => {
    const manager = fixture();
    const envelope = await seal(manager);
    for (const change of [
      { nonce: '' },
      { nonce: `${envelope.nonce}\n` },
      {
        ciphertext: 'A'.repeat(
          4 * Math.ceil((MAX_PRIVATE_RECORD_BYTES + 16) / 3) + 4
        ),
      },
      { ciphertext: 'AA==' },
      { secret: 'unexpected metadata' },
    ]) {
      await expect(open(manager, { ...envelope, ...change })).rejects.toThrow(
        'envelope'
      );
    }
  });

  it('requires an unlocked session and native WebCrypto', async () => {
    const manager = fixture();
    const envelope = await seal(manager);
    await manager.lockWallet();
    await expect(manager.getPrivateRecordProfileId()).rejects.toThrow(
      'session changed'
    );
    await expect(seal(manager)).rejects.toThrow('session changed');
    await expect(open(manager, envelope)).rejects.toThrow('session changed');
    installSession(manager);
    global.crypto = undefined as any;
    await expect(seal(manager)).rejects.toThrow('cryptography unavailable');
  });
});

describe('private record async session lifetime', () => {
  it.each([
    ['profile', 'importKey'],
    ['profile', 'deriveBits'],
    ['encrypt', 'importKey'],
    ['encrypt', 'deriveBits'],
    ['encrypt', 'deriveKey'],
    ['encrypt', 'encrypt'],
    ['decrypt', 'importKey'],
    ['decrypt', 'deriveBits'],
    ['decrypt', 'deriveKey'],
    ['decrypt', 'decrypt'],
  ] as const)('rejects %s after lock during %s', async (operation, method) => {
    const manager = fixture();
    const envelope = await seal(manager);
    const pause = pauseCrypto(method);
    const pending =
      operation === 'profile'
        ? manager.getPrivateRecordProfileId()
        : operation === 'encrypt'
        ? seal(manager)
        : open(manager, envelope);
    await pause.started;
    await manager.lockWallet();
    pause.release();
    await expect(pending).rejects.toThrow('session changed');
    if (method === 'decrypt') {
      expect(
        new Uint8Array(pause.output() as ArrayBuffer).every(
          (value) => value === 0
        )
      ).toBe(true);
    }
    if (method === 'encrypt') {
      expect((pause.input() as Uint8Array).every((value) => value === 0)).toBe(
        true
      );
    }
  });

  it.each(['replace', 'transfer', 'transfer-back'] as const)(
    'rejects a pending result after %s',
    async (change) => {
      const source = fixture();
      const target = fixture('another root');
      const pause = pauseCrypto('encrypt');
      const pending = seal(source);
      await pause.started;
      if (change === 'replace') installSession(source);
      else {
        source.transferSessionTo(target);
        if (change === 'transfer-back') target.transferSessionTo(source);
      }
      pause.release();
      await expect(pending).rejects.toThrow('session changed');
    }
  );

  it('keeps record identity and ciphertext valid after a completed session transfer', async () => {
    const source = fixture();
    const target = fixture('another root');
    const profile = await source.getPrivateRecordProfileId();
    const envelope = await seal(source);
    source.transferSessionTo(target);
    expect(source.isUnlocked()).toBe(false);
    expect(await target.getPrivateRecordProfileId()).toBe(profile);
    expect(await open(target, envelope)).toEqual(bytes());
  });
});
