import { createHash } from 'crypto';

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
const credential: SecretOperationCredentialPort = {
  async withSecret(check, consume) {
    check();
    await consume(password);
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

async function fixture(policy: 'operation' | 'session' = 'operation') {
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
    password
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
    await ring.withSecretOperation(credential, options(), async () => {
      profile = await ring.getPrivateRecordProfileId();
      record = await ring.encryptPrivateRecord({
        domain: domains[0],
        recordId: 'record-1',
        plaintext: new Uint8Array([1, 2, 3]),
      });
      checkpoint = await ring.createPublicSessionCheckpoint(request, noop);
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
      f.ring.createPublicSessionCheckpoint(f.request, noop)
    ).rejects.toThrow('secret operation');
    expect(decrypt).not.toHaveBeenCalled();
    expect(persistence).not.toHaveBeenCalled();
    expect(signer).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();
    expect(root).not.toHaveBeenCalled();
    expect(seed).not.toHaveBeenCalled();
  } finally {
    decrypt.mockRestore();
    persistence.mockRestore();
    signer.mockRestore();
    unlock.mockRestore();
    root.mockRestore();
    seed.mockRestore();
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
        async withSecret(check, consume) {
          entered.resolve();
          await held.promise;
          check();
          await consume(password);
        },
      },
      { ...f.request, checkpoint: f.checkpoint },
      options(abort.signal),
      delivered
    );
    const failed = expect(pending).rejects.toThrow();
    await entered.promise;
    await expect(
      f.ring.withSecretOperation(credential, options(), noop)
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
    await f.ring.withSecretOperation(credential, options(), async () => {
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
        async withSecret(check, consume) {
          entered.resolve();
          await held.promise;
          check();
          await consume(password);
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
  let consume: ((secret: string) => Promise<void>) | undefined;
  try {
    await expect(
      f.ring.restorePublicSession(
        {
          async withSecret(_check, callback) {
            consume = callback;
          },
        },
        { ...f.request, checkpoint: f.checkpoint },
        options(),
        noop
      )
    ).rejects.toThrow('not consumed');
    await expect(consume!(password)).rejects.toThrow('cancelled');
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
      noop
    );
    expect(checkpoint.domain).toBe('sysweb3.public-session.v1');
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
