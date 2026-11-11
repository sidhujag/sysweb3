import { createHash } from 'crypto';

import * as privateRecords from '../../../src/private-records';
import {
  SoftwareKeyring,
  createKeyringHost,
  KeyringAccountType,
  INetworkType,
} from '../../../src/software';
import * as storageCrypto from '../../../src/storage-core';

import type { IEncryptedPrivateRecord } from '../../../src/private-records';
import type {
  KeyringStoragePort,
  SecretOperationCredentialPort,
  PublicSessionCredentialPort,
} from '../../../src/software';

const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public session fixture credential';
const walletBindingId = 'ab'.repeat(32);
const domains = ['fixture.public.root.v1', 'fixture.public.chunk.v1'];
const manifest = new TextEncoder().encode(
  JSON.stringify({
    accounts: [{ id: 'hd:60:0', address: 'fixture-address' }],
    networks: ['ethereum'],
  })
);
const noop = () => undefined;
const options = (signal = new AbortController().signal) => ({
  signal,
  assertCurrent: noop,
});
const secretCredential: SecretOperationCredentialPort = {
  async withSecret(check, consume) {
    check();
    await consume(password);
    check();
  },
};
const publicKey = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
const credential: PublicSessionCredentialPort = {
  async withKey(check, consume) {
    check();
    await consume(publicKey);
    check();
  },
};
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

async function fixture(
  policy: 'operation' | 'session' = 'operation',
  fixturePassword = password
) {
  const records = new Map<string, any>();
  const storage: KeyringStoragePort = {
    async get(key) {
      return records.get(key);
    },
    async set(key, value) {
      records.set(key, value);
    },
    async deleteItem(key) {
      records.delete(key);
    },
    async createManyIfAbsent(items) {
      if (Object.keys(items).some((key) => records.has(key))) return false;
      Object.entries(items).forEach(([key, value]) => records.set(key, value));
      return true;
    },
    async readDeviceUnlockVaultPair() {
      const vault = records.get('vault'),
        keys = records.get('vault-keys');
      if (!vault || !keys) return null;
      return {
        vault,
        keys,
        pairFingerprint: createHash('sha256')
          .update(JSON.stringify([vault, keys]))
          .digest('hex'),
      };
    },
  };
  const ring = new SoftwareKeyring(createKeyringHost(storage), {
    secretLifetime: policy,
    captureEvmSubmission: null,
  });
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
  ring.setVaultStateGetter(() => state);
  state.accounts.HDAccount[0] = await ring.initializeWalletSecurely(
    phrase,
    fixturePassword
  );
  const request = {
    walletBindingId,
    publicState: manifest,
    recordDomains: domains,
  };
  let checkpoint!: IEncryptedPrivateRecord,
    record!: IEncryptedPrivateRecord,
    profile!: string;
  if (policy === 'operation') {
    await ring.withSecretOperation(secretCredential, options(), async () => {
      profile = await ring.getPrivateRecordProfileId();
      record = await ring.encryptPrivateRecord({
        domain: domains[0],
        recordId: 'record-1',
        plaintext: new Uint8Array([1, 2, 3]),
      });
      checkpoint = await ring.createPublicSessionCheckpoint(
        request,
        publicKey,
        noop
      );
    });
    await ring.lockWallet();
  }
  return { ring, records, state, request, checkpoint, record, profile };
}

it('restores authenticated public state and v1 record keys without ever opening the vault or software signer', async () => {
  const f = await fixture();
  const decrypt = jest
    .spyOn(storageCrypto, 'decryptCurrentVault')
    .mockImplementation(async () => {
      throw Error('vault decryption forbidden');
    });
  const persistence = jest
    .spyOn((f.ring as any).vaultPersistence, 'getDecryptedVault')
    .mockImplementation(async () => {
      throw Error('vault persistence decryption forbidden');
    });
  const signer = jest
    .spyOn(f.ring as any, 'getSigner')
    .mockImplementation(() => {
      throw Error('software signer forbidden');
    });
  const unlock = jest
    .spyOn(f.ring as any, 'unlockSession')
    .mockImplementation(() => {
      throw Error('root unlock forbidden');
    });
  const root = jest
    .spyOn(f.ring as any, 'getDecryptedMnemonic')
    .mockImplementation(() => {
      throw Error('root read forbidden');
    });
  const seed = jest
    .spyOn(f.ring as any, 'withSecureData')
    .mockImplementation(() => {
      throw Error('software secret forbidden');
    });
  const derive = jest
    .spyOn(f.ring as any, 'deriveStoredSessionKey')
    .mockImplementation(() => {
      throw Error('vault key derivation forbidden');
    });
  try {
    expect(
      await f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        async (bytes) => {
          expect(Array.from(bytes)).toEqual(Array.from(manifest));
          expect(f.ring.hasPublicSession()).toBe(true);
          expect(f.ring.isUnlocked()).toBe(false);
          expect((f.ring as any).sessionPassword).toBeNull();
          expect((f.ring as any).sessionMnemonic).toBeNull();
          return 'public-ready';
        }
      )
    ).toBe('public-ready');
    const access = f.ring.getPrivateRecordAccess(domains);
    expect(await access.getPrivateRecordProfileId()).toBe(f.profile);
    expect(
      await access.decryptPrivateRecord({
        domain: domains[0],
        recordId: 'record-1',
        envelope: f.record,
      })
    ).toEqual(new Uint8Array([1, 2, 3]));
    expect(() =>
      f.ring.getPrivateRecordAccess(['fixture.private.notes.v1'])
    ).toThrow();
    await expect(
      f.ring.createPublicSessionCheckpoint(f.request, publicKey, noop)
    ).rejects.toThrow('secret operation');
    expect(decrypt).not.toHaveBeenCalled();
    expect(persistence).not.toHaveBeenCalled();
    expect(signer).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();
    expect(root).not.toHaveBeenCalled();
    expect(seed).not.toHaveBeenCalled();
    expect(derive).not.toHaveBeenCalled();
  } finally {
    decrypt.mockRestore();
    persistence.mockRestore();
    signer.mockRestore();
    unlock.mockRestore();
    root.mockRestore();
    seed.mockRestore();
    derive.mockRestore();
    await f.ring.destroy();
  }
});

it('does not accept the wallet password or vault key as the public checkpoint credential', async () => {
  const f = await fixture();
  let vaultKey: Uint8Array | undefined;
  const delivered = jest.fn();
  try {
    await f.ring.withSecretOperation(secretCredential, options(), async () => {
      vaultKey = new Uint8Array(
        Buffer.from((f.ring as any).sessionPassword.toString(), 'hex')
      );
    });
    await f.ring.lockWallet();
    await expect(
      f.ring.restorePublicSession(
        secretCredential as any,
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        delivered
      )
    ).rejects.toThrow('Invalid public session restore');
    for (const key of [
      password,
      vaultKey,
      new Uint8Array(31),
      new Uint8Array(33),
    ]) {
      await expect(
        f.ring.restorePublicSession(
          {
            async withKey(_check, consume) {
              await consume(key as any);
            },
          },
          { ...f.request, checkpoint: f.checkpoint },
          options(),
          delivered
        )
      ).rejects.toThrow();
    }
    expect(delivered).not.toHaveBeenCalled();
    expect(f.ring.hasPublicSession()).toBe(false);
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    vaultKey?.fill(0);
    await f.ring.destroy();
  }
});

it('a public checkpoint key cannot decrypt the wallet or authorize a secret operation', async () => {
  const f = await fixture();
  const work = jest.fn();
  const keyHex = Buffer.from(publicKey).toString('hex');
  try {
    await expect(
      storageCrypto.decryptCurrentVault(f.records.get('vault'), keyHex)
    ).rejects.toThrow();
    await expect(
      f.ring.withSecretOperation(
        {
          async withSecret(_check, consume) {
            await consume(keyHex);
          },
        },
        options(),
        work
      )
    ).rejects.toThrow();
    expect(work).not.toHaveBeenCalled();
    await f.ring.restorePublicSession(
      credential,
      { ...f.request, checkpoint: f.checkpoint },
      options(),
      noop
    );
    expect(f.ring.hasPublicSession()).toBe(true);
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('requires a separate exact 32-byte wrapping key at checkpoint creation', async () => {
  const f = await fixture('session');
  const vaultKey = new Uint8Array(
    Buffer.from((f.ring as any).sessionPassword.toString(), 'hex')
  );
  try {
    for (const key of [
      undefined,
      password,
      new Uint8Array(31),
      new Uint8Array(33),
    ]) {
      await expect(
        f.ring.createPublicSessionCheckpoint(f.request, key as any, noop)
      ).rejects.toThrow('Invalid public session key');
    }
    await expect(
      (f.ring.createPublicSessionCheckpoint as any)(f.request, noop)
    ).rejects.toThrow('Invalid public session key');
    await expect(
      f.ring.createPublicSessionCheckpoint(f.request, vaultKey, noop)
    ).rejects.toThrow('independent of the vault key');
    expect(f.ring.isUnlocked()).toBe(true);
    expect(await f.ring.getSeed(password)).toBe(phrase);
  } finally {
    vaultKey.fill(0);
    await f.ring.destroy();
  }
});

it.each(['own', 'subclass'] as const)(
  'rejects a %s length override hiding more than 32 key bytes',
  async (kind) => {
    const f = await fixture('session');
    const Key = class extends Uint8Array {};
    if (kind === 'subclass')
      Object.defineProperty(Key.prototype, 'length', { get: () => 32 });
    const key = kind === 'own' ? new Uint8Array(71) : new Key(71);
    if (kind === 'own') Object.defineProperty(key, 'length', { value: 32 });
    try {
      expect(key.length).toBe(32);
      expect(new Uint8Array(key).length).toBe(71);
      await expect(
        f.ring.createPublicSessionCheckpoint(f.request, key, noop)
      ).rejects.toThrow('Invalid public session key');
    } finally {
      key.fill(0);
      await f.ring.destroy();
    }
  }
);

it('rejects reusing an exact 32-byte UTF-8 vault password as the public key', async () => {
  const fixturePassword = '0123456789abcdef0123456789abcdef';
  const f = await fixture('session', fixturePassword);
  const key = new TextEncoder().encode(fixturePassword);
  try {
    expect(key.length).toBe(32);
    await expect(
      f.ring.createPublicSessionCheckpoint(f.request, key, noop)
    ).rejects.toThrow('independent of the vault');
    expect(f.ring.isUnlocked()).toBe(true);
    expect(await f.ring.getSeed(fixturePassword)).toBe(phrase);
  } finally {
    key.fill(0);
    await f.ring.destroy();
  }
});

it('rejects an authenticated original-format checkpoint with its original vault key', async () => {
  const f = await fixture();
  let vaultKey: Uint8Array | undefined, payload: Uint8Array | undefined;
  const delivered = jest.fn();
  try {
    await f.ring.withSecretOperation(secretCredential, options(), async () => {
      vaultKey = new Uint8Array(
        Buffer.from((f.ring as any).sessionPassword.toString(), 'hex')
      );
    });
    await f.ring.lockWallet();
    payload = await privateRecords.decryptPrivateRecordBytes(
      publicKey,
      {
        domain: f.checkpoint.domain,
        recordId: walletBindingId,
        envelope: f.checkpoint,
      },
      noop
    );
    // This is the previous checkpoint's exact authenticated payload and domain,
    // including its original header and seed-derived record keys.
    payload.set([0x50, 0x53, 0x43, 1]);
    const legacy = await privateRecords.encryptPrivateRecordBytes(
      vaultKey!,
      {
        domain: 'sysweb3.public-session.v1',
        recordId: walletBindingId,
        plaintext: payload,
      },
      noop
    );
    const verified = await privateRecords.decryptPrivateRecordBytes(
      vaultKey!,
      {
        domain: 'sysweb3.public-session.v1',
        recordId: walletBindingId,
        envelope: legacy,
      },
      noop
    );
    expect(Array.from(verified)).toEqual(Array.from(payload));
    verified.fill(0);
    await expect(
      f.ring.restorePublicSession(
        {
          async withKey(_check, consume) {
            await consume(vaultKey!);
          },
        },
        { ...f.request, checkpoint: legacy },
        options(),
        delivered
      )
    ).rejects.toThrow();
    expect(delivered).not.toHaveBeenCalled();
    expect(f.ring.hasPublicSession()).toBe(false);
    // Rewrapping under the new domain cannot make the original payload header
    // valid either; the format marker is checked independently after AEAD.
    const oldHeader = await privateRecords.encryptPrivateRecordBytes(
      publicKey,
      {
        domain: f.checkpoint.domain,
        recordId: walletBindingId,
        plaintext: payload,
      },
      noop
    );
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: oldHeader },
        options(),
        delivered
      )
    ).rejects.toThrow('context changed');
    expect(delivered).not.toHaveBeenCalled();
  } finally {
    payload?.fill(0);
    vaultKey?.fill(0);
    await f.ring.destroy();
  }
});

it('owns and clears public wrapping-key copies without modifying caller keys', async () => {
  const f = await fixture();
  const key = new Uint8Array(publicKey);
  const copies: Uint8Array[] = [];
  const seal = privateRecords.sealPublicRecordCheckpoint;
  const restore = privateRecords.restorePublicRecordCheckpoint;
  const sealing = jest
    .spyOn(privateRecords, 'sealPublicRecordCheckpoint')
    .mockImplementation((...args) => {
      copies.push(args[1]);
      return seal(...args);
    });
  const restoring = jest
    .spyOn(privateRecords, 'restorePublicRecordCheckpoint')
    .mockImplementation((...args) => {
      copies.push(args[0]);
      return restore(...args);
    });
  let checkpoint!: IEncryptedPrivateRecord;
  try {
    await f.ring.withSecretOperation(secretCredential, options(), async () => {
      checkpoint = await f.ring.createPublicSessionCheckpoint(
        f.request,
        key,
        () => {
          key.fill(99);
        }
      );
    });
    await f.ring.lockWallet();
    key.set(publicKey);
    await f.ring.restorePublicSession(
      {
        async withKey(_check, consume) {
          const pending = consume(key);
          key.fill(99);
          await pending;
        },
      },
      { ...f.request, checkpoint },
      options(),
      noop
    );
    expect(Array.from(publicKey)).toEqual(
      Array.from({ length: 32 }, (_, index) => index + 1)
    );
    expect(Array.from(key)).toEqual(Array(32).fill(99));
    expect(copies).toHaveLength(2);
    for (const copy of copies)
      expect(Array.from(copy)).toEqual(Array(32).fill(0));
    expect(f.ring.hasPublicSession()).toBe(true);
  } finally {
    sealing.mockRestore();
    restoring.mockRestore();
    key.fill(0);
    await f.ring.destroy();
  }
});

it.each(['manifest', 'wallet', 'domain', 'pair', 'ciphertext'] as const)(
  'rejects changed %s without delivering public state or loading a root',
  async (change) => {
    const f = await fixture(),
      delivered = jest.fn();
    const unlock = jest
      .spyOn(f.ring as any, 'unlockSession')
      .mockImplementation(() => {
        throw Error('root unlock forbidden');
      });
    try {
      const request = { ...f.request, checkpoint: f.checkpoint };
      if (change === 'manifest') request.publicState = new Uint8Array([99]);
      if (change === 'wallet') request.walletBindingId = 'cd'.repeat(32);
      if (change === 'domain')
        request.recordDomains = ['fixture.private.notes.v1'];
      if (change === 'pair')
        f.records.set('vault', f.records.get('vault') + ' ');
      if (change === 'ciphertext')
        request.checkpoint = {
          ...f.checkpoint,
          ciphertext:
            (f.checkpoint.ciphertext[0] === 'A' ? 'B' : 'A') +
            f.checkpoint.ciphertext.slice(1),
        };
      await expect(
        f.ring.restorePublicSession(credential, request, options(), delivered)
      ).rejects.toThrow();
      expect(delivered).not.toHaveBeenCalled();
      expect(unlock).not.toHaveBeenCalled();
      expect(f.ring.hasPublicSession()).toBe(false);
      expect(f.ring.isUnlocked()).toBe(false);
      expect(() => f.ring.getPrivateRecordAccess(domains)).toThrow();
    } finally {
      unlock.mockRestore();
      await f.ring.destroy();
    }
  }
);

it('has no missing-checkpoint fallback and does not invoke accessor requests', async () => {
  const f = await fixture(),
    getter = jest.fn(() => manifest);
  try {
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: undefined } as any,
        options(),
        noop
      )
    ).rejects.toThrow();
    const request = Object.defineProperty(
      { ...f.request, checkpoint: f.checkpoint },
      'publicState',
      { get: getter }
    );
    await expect(
      f.ring.restorePublicSession(credential, request, options(), noop)
    ).rejects.toThrow();
    expect(getter).not.toHaveBeenCalled();
    expect(f.ring.hasPublicSession()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('cancels a held proof, refuses concurrent secret work and never delivers late state', async () => {
  const f = await fixture(),
    held = deferred(),
    entered = deferred(),
    abort = new AbortController(),
    delivered = jest.fn();
  try {
    const pending = f.ring.restorePublicSession(
      {
        async withKey(check, consume) {
          entered.resolve();
          await held.promise;
          check();
          await consume(publicKey);
        },
      },
      { ...f.request, checkpoint: f.checkpoint },
      options(abort.signal),
      delivered
    );
    const failed = expect(pending).rejects.toThrow();
    await entered.promise;
    await expect(
      f.ring.withSecretOperation(secretCredential, options(), noop)
    ).rejects.toThrow('busy');
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        noop
      )
    ).rejects.toThrow();
    abort.abort();
    held.resolve();
    await failed;
    expect(delivered).not.toHaveBeenCalled();
    expect(f.ring.hasPublicSession()).toBe(false);
    expect((f.ring as any).sessionPassword).toBeNull();
    expect((f.ring as any).sessionMnemonic).toBeNull();
  } finally {
    held.resolve();
    await f.ring.destroy();
  }
});

it('retires restored capabilities if guarded public hydration fails', async () => {
  const f = await fixture();
  let access: ReturnType<SoftwareKeyring['getPrivateRecordAccess']> | undefined;
  try {
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        () => {
          access = f.ring.getPrivateRecordAccess(domains);
          throw Error('public hydration failed');
        }
      )
    ).rejects.toThrow('public hydration failed');
    expect(f.ring.hasPublicSession()).toBe(false);
    await expect(access!.getPrivateRecordProfileId()).rejects.toThrow();
  } finally {
    await f.ring.destroy();
  }
});

it('still requires an independent secret operation to access the root after public restoration', async () => {
  const f = await fixture();
  try {
    await f.ring.restorePublicSession(
      credential,
      { ...f.request, checkpoint: f.checkpoint },
      options(),
      noop
    );
    await expect(f.ring.getSeed(password)).rejects.toThrow();
    await f.ring.withSecretOperation(secretCredential, options(), async () => {
      expect(await f.ring.getSeed(password)).toBe(phrase);
    });
    expect(f.ring.isUnlocked()).toBe(false);
    expect(f.ring.hasPublicSession()).toBe(true);
    await f.ring.lockWallet();
    expect(() => f.ring.getPrivateRecordAccess(domains)).toThrow();
  } finally {
    await f.ring.destroy();
  }
});

it('leaves extension session policy unchanged and refuses this mobile-only restore seam', async () => {
  const f = await fixture('session');
  try {
    expect(f.ring.isUnlocked()).toBe(true);
    expect(await f.ring.getSeed(password)).toBe(phrase);
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: {} as any },
        options(),
        noop
      )
    ).rejects.toThrow('Operation secret policy');
    expect(f.ring.isUnlocked()).toBe(true);
  } finally {
    await f.ring.destroy();
  }
});

it('aborting held public hydration immediately revokes its record capability and rejects its late result', async () => {
  const f = await fixture(),
    entered = deferred(),
    held = deferred(),
    abort = new AbortController();
  let access: ReturnType<SoftwareKeyring['getPrivateRecordAccess']> | undefined;
  try {
    const pending = f.ring.restorePublicSession(
      credential,
      { ...f.request, checkpoint: f.checkpoint },
      options(abort.signal),
      async () => {
        access = f.ring.getPrivateRecordAccess(domains);
        entered.resolve();
        await held.promise;
        return 'late';
      }
    );
    const rejected = expect(pending).rejects.toThrow();
    await entered.promise;
    abort.abort();
    expect(f.ring.hasPublicSession()).toBe(false);
    await expect(access!.getPrivateRecordProfileId()).rejects.toThrow();
    held.resolve();
    await rejected;
    expect(f.ring.isUnlocked()).toBe(false);
    expect(f.ring.hasPublicSession()).toBe(false);
  } finally {
    held.resolve();
    await f.ring.destroy();
  }
});

it('uses the captured immutable manifest despite caller mutation while its proof is pending', async () => {
  const f = await fixture(),
    entered = deferred(),
    held = deferred();
  const bytes = new Uint8Array(manifest);
  try {
    const pending = f.ring.restorePublicSession(
      {
        async withKey(check, consume) {
          entered.resolve();
          await held.promise;
          check();
          await consume(publicKey);
        },
      },
      { ...f.request, publicState: bytes, checkpoint: f.checkpoint },
      options(),
      (actual) => Array.from(actual)
    );
    await entered.promise;
    bytes.fill(99);
    held.resolve();
    expect(await pending).toEqual(Array.from(manifest));
  } finally {
    held.resolve();
    await f.ring.destroy();
  }
});

it('a credential callback retained after its owner settles cannot restore a session', async () => {
  const f = await fixture();
  let consume: ((key: Uint8Array) => Promise<void>) | undefined;
  try {
    await expect(
      f.ring.restorePublicSession(
        {
          async withKey(_check, callback) {
            consume = callback;
          },
        },
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        noop
      )
    ).rejects.toThrow('not consumed');
    await expect(consume!(publicKey)).rejects.toThrow('cancelled');
    expect(f.ring.hasPublicSession()).toBe(false);
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('creates the checkpoint from an already-authorized staging session without a second unlock', async () => {
  const f = await fixture('session');
  const unlock = jest
    .spyOn(f.ring as any, 'unlockSession')
    .mockImplementation(() => {
      throw Error('second unlock forbidden');
    });
  try {
    const checkpoint = await f.ring.createPublicSessionCheckpoint(
      f.request,
      publicKey,
      noop
    );
    expect(checkpoint.domain).toBe('sysweb3.public-view.v1');
    expect(unlock).not.toHaveBeenCalled();
    expect(f.ring.isUnlocked()).toBe(true);
  } finally {
    unlock.mockRestore();
    await f.ring.destroy();
  }
});

it('fails closed when the atomic pair changes during guarded public hydration', async () => {
  const f = await fixture();
  let access: ReturnType<SoftwareKeyring['getPrivateRecordAccess']> | undefined;
  try {
    await expect(
      f.ring.restorePublicSession(
        credential,
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        () => {
          access = f.ring.getPrivateRecordAccess(domains);
          f.records.set('vault', f.records.get('vault') + ' ');
          return 'not-delivered';
        }
      )
    ).rejects.toThrow('wallet changed');
    expect(f.ring.hasPublicSession()).toBe(false);
    await expect(access!.getPrivateRecordProfileId()).rejects.toThrow();
  } finally {
    await f.ring.destroy();
  }
});

it('rejects a restore when its initial host guard synchronously locks the wallet', async () => {
  const f = await fixture();
  const consumed = jest.fn(credential.withKey);
  const delivered = jest.fn();
  let locked: Promise<void> | undefined;
  try {
    await expect(
      f.ring.restorePublicSession(
        { withKey: consumed },
        { ...f.request, checkpoint: f.checkpoint },
        {
          signal: new AbortController().signal,
          assertCurrent() {
            locked ??= f.ring.lockWallet();
          },
        },
        delivered
      )
    ).rejects.toThrow();
    await locked;
    expect(consumed).not.toHaveBeenCalled();
    expect(delivered).not.toHaveBeenCalled();
    expect(f.ring.hasPublicSession()).toBe(false);
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await locked;
    await f.ring.destroy();
  }
});

it.each(['restore', 'secret'] as const)(
  'does not replace the %s operation admitted by its initial host guard',
  async (kind) => {
    const f = await fixture();
    const consumed = jest.fn(credential.withKey),
      delivered = jest.fn();
    let nested: Promise<string> | undefined;
    try {
      const outer = f.ring.restorePublicSession(
        { withKey: consumed },
        { ...f.request, checkpoint: f.checkpoint },
        {
          signal: new AbortController().signal,
          assertCurrent() {
            if (!nested) {
              nested =
                kind === 'restore'
                  ? f.ring.restorePublicSession(
                      credential,
                      { ...f.request, checkpoint: f.checkpoint },
                      options(),
                      () => 'winner'
                    )
                  : f.ring.withSecretOperation(
                      secretCredential,
                      options(),
                      async () => 'winner'
                    );
              void nested.catch(() => undefined);
            }
          },
        },
        delivered
      );
      await expect(outer).rejects.toThrow();
      expect(nested).toBeDefined();
      expect(await nested).toBe('winner');
      expect(consumed).not.toHaveBeenCalled();
      expect(delivered).not.toHaveBeenCalled();
      expect(f.ring.hasPublicSession()).toBe(true);
      expect(f.ring.isUnlocked()).toBe(false);
    } finally {
      await nested?.catch(() => undefined);
      await f.ring.destroy();
    }
  }
);
