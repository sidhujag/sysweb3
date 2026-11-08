'use strict';
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const path = require('node:path');
const test = require('node:test');

globalThis.fetch = () => {
  throw new Error('Browser custody fixture attempted network access');
};
process.env.NODE_ENV = 'test';
process.env.SYSWEB3_PBKDF2_ENC_ITERS = '1000';
const compiled = path.resolve(
  process.argv[2] || path.join(__dirname, '../dist/cjs')
);
const sdk = require(path.join(compiled, 'index.js'));
const {
  createKeyringHost,
  KeyringManager,
  HardwareWalletManager,
  HardwareWalletType,
  KeyringAccountType,
} = sdk;
const { createTrezorWebExtensionHost } = require(path.join(
  compiled,
  'trezor/webextension-host.js'
));
const trezorHost = () =>
  createTrezorWebExtensionHost({
    manifest: {
      appName: 'Fixture',
      appUrl: 'https://example.invalid',
      email: 'test@example.invalid',
    },
  });
const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public browser fixture password';
const current = () => undefined;

function deferred() {
  let resolve;
  const promise = new Promise((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function fixture() {
  const records = new Map();
  let saved,
    waitForRead,
    pairFailure,
    reads = 0,
    writes = 0,
    singleReads = 0;
  const storage = {
    async get(key) {
      singleReads++;
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
      for (const [key, value] of Object.entries(items)) records.set(key, value);
      return true;
    },
    async readDeviceUnlockVaultPair() {
      if (pairFailure) throw pairFailure;
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
  const port = {
    async readCredential() {
      reads++;
      await waitForRead?.();
      return saved && { ...saved, key: saved.key.slice() };
    },
    async writeCredential(credential, guard) {
      guard();
      writes++;
      saved = { ...credential, key: credential.key.slice() };
    },
  };
  return {
    storage,
    port,
    blockRead(blocker) {
      waitForRead = blocker;
    },
    failPair(error) {
      pairFailure = error;
    },
    counts: () => ({ reads, writes, singleReads }),
  };
}

const offlineLedger = {
  evm: {},
  utxo: {},
  async connect() {},
  async disconnect() {},
  async retire() {
    return () => {};
  },
  getStatus: () => ({ connected: false }),
};

function manager(host, receive = true, hardwareManager, ledgerHost) {
  let controls;
  const options = {
    trezorHost: trezorHost(),
    captureEvmSubmission() {
      throw new Error('EVM submission is outside this fixture');
    },
    ...(hardwareManager
      ? { hardwareManager }
      : { ledgerHost: ledgerHost ?? offlineLedger }),
    ...(receive
      ? {
          receiveDeviceUnlock: (value) => {
            controls = value;
          },
        }
      : {}),
  };
  const ring = new KeyringManager(host, options);
  const state = {
    activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
    activeNetwork: {
      kind: 'ethereum',
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
  return { ring, state, controls };
}

async function initialize(owner) {
  owner.state.accounts.HDAccount[0] = await owner.ring.initializeWalletSecurely(
    phrase,
    password
  );
}

test('compiled browser owner shares controls and one session across replacement managers', async () => {
  const f = fixture(),
    other = fixture();
  const host = createKeyringHost(f.storage, { deviceUnlock: f.port });
  const source = manager(host),
    target = manager(host),
    fresh = manager(host);
  const foreign = manager(
    createKeyringHost(other.storage, { deviceUnlock: other.port })
  );
  try {
    await initialize(source);
    await initialize(foreign);
    target.state.accounts.HDAccount[0] = fresh.state.accounts.HDAccount[0] =
      source.state.accounts.HDAccount[0];
    assert.equal('setStorage' in source.ring, false);
    assert.equal('receiveSessionOwnership' in source.ring, false);
    assert.equal(await source.controls.issue('wrong password', current), false);
    assert.equal(f.counts().writes, 0);
    assert.equal(await source.controls.issue(password, current), true);
    await assert.rejects(
      source.ring.prepareSessionTransfer(foreign.ring, current),
      /different wallet authorities/
    );
    assert.equal(foreign.ring.isUnlocked(), true);
    (
      await source.ring.prepareSessionTransfer(target.ring, () => undefined)
    ).transfer();
    assert.equal(source.ring.isUnlocked(), false);
    assert.equal(target.ring.isUnlocked(), true);
    await target.ring.lockWallet();
    await assert.rejects(source.controls.resume(current), /session changed/);
    assert.equal(f.counts().reads, 0);
    assert.equal(await fresh.controls.resume(current), true);
    assert.equal(await fresh.ring.getSeed(password), phrase);
    await assert.rejects(fresh.ring.getSeed('wrong password'));
    assert.equal(other.counts().reads, 0);
  } finally {
    await Promise.all(
      [source, target, fresh, foreign].map(({ ring }) => ring.destroy())
    );
  }
});

test('compiled receiver-free browser sibling wins over held protected read', async () => {
  const f = fixture(),
    entered = deferred(),
    release = deferred();
  const host = createKeyringHost(f.storage, { deviceUnlock: f.port });
  const source = manager(host),
    contender = manager(host),
    winner = manager(host, false);
  try {
    await initialize(source);
    contender.state.accounts.HDAccount[0] = winner.state.accounts.HDAccount[0] =
      source.state.accounts.HDAccount[0];
    assert.equal(await source.controls.issue(password, current), true);
    await source.ring.lockWallet();
    f.blockRead(async () => {
      entered.resolve();
      await release.promise;
    });
    const pending = contender.controls.resume(current);
    await entered.promise;
    assert.equal((await winner.ring.unlock(password)).canLogin, true);
    release.resolve();
    await assert.rejects(pending, /session is owned by another keyring/);
    assert.equal(contender.ring.isUnlocked(), false);
    assert.equal(winner.ring.isUnlocked(), true);
  } finally {
    release.resolve();
    await Promise.all(
      [source, contender, winner].map(({ ring }) => ring.destroy())
    );
  }
});

test('compiled browser host rejects missing atomic storage and never falls back after a read error', async () => {
  const f = fixture(),
    failure = new Error('Atomic fixture read failed');
  assert.throws(
    () =>
      createKeyringHost(
        { ...f.storage, readDeviceUnlockVaultPair: undefined },
        { deviceUnlock: f.port }
      ),
    /atomic vault pair reader/
  );
  assert.throws(
    () =>
      createKeyringHost(
        { ...f.storage, setClient() {} },
        { deviceUnlock: f.port }
      ),
    /fixed wallet storage/
  );
  assert.throws(
    () =>
      new KeyringManager(
        {},
        {
          trezorHost: trezorHost(),
          captureEvmSubmission: () => {
            throw new Error('EVM submission is outside this fixture');
          },
          ledgerHost: offlineLedger,
        }
      ),
    /Invalid keyring host/
  );
  const owner = manager(createKeyringHost(f.storage, { deviceUnlock: f.port }));
  try {
    f.failPair(failure);
    const counts = f.counts();
    await assert.rejects(
      owner.controls.resume(current),
      (error) => error === failure
    );
    assert.deepEqual(f.counts(), counts);
    assert.equal(owner.ring.isUnlocked(), false);
  } finally {
    await owner.ring.destroy();
  }
});

test('compiled fixed browser host preserves the existing storage namespace without biometrics', async () => {
  assert.equal(sdk.getDecryptedVault, undefined);
  assert.equal(sdk.setEncryptedVault, undefined);
  assert.equal(sdk.HardwareWalletManagerSingleton, undefined);
  assert.equal(sdk.createKeyringManagerHost, undefined);
  const records = new Map();
  const keyFor = (key) => `sysweb3-${key}`;
  const host = createKeyringHost({
    async get(key) {
      return records.get(keyFor(key));
    },
    async set(key, value) {
      records.set(keyFor(key), value);
    },
    async deleteItem(key) {
      records.delete(keyFor(key));
    },
    async createManyIfAbsent(items) {
      const entries = Object.entries(items);
      if (entries.some(([key]) => records.has(keyFor(key)))) return false;
      for (const [key, value] of entries) records.set(keyFor(key), value);
      return true;
    },
  });
  const owner = manager(host, false);
  const sibling = manager(host, false);
  try {
    assert.throws(
      () =>
        new KeyringManager(undefined, {
          trezorHost: trezorHost(),
          captureEvmSubmission: () => {
            throw new Error('EVM submission is outside this fixture');
          },
          ledgerHost: offlineLedger,
        }),
      /Invalid keyring host/
    );
    assert.throws(() => manager(host), /unavailable in this host/);
    await initialize(owner);
    assert.ok(
      records.has('sysweb3-vault') && records.has('sysweb3-vault-keys')
    );
    assert.equal(owner.controls, undefined);
    assert.equal(Reflect.has(owner.ring, 'issue'), false);
    assert.equal(Reflect.has(owner.ring, 'resume'), false);
    assert.equal(typeof owner.ring.ledgerSigner.ensureConnection, 'function');
    await assert.rejects(
      sibling.ring.unlock(password),
      /owned by another keyring/
    );
    sibling.state.accounts.HDAccount[0] = owner.state.accounts.HDAccount[0];
    (
      await owner.ring.prepareSessionTransfer(sibling.ring, () => undefined)
    ).transfer();
    assert.equal(owner.ring.isUnlocked(), false);
    assert.equal(sibling.ring.isUnlocked(), true);
    assert.equal(await sibling.ring.getSeed(password), phrase);
  } finally {
    await owner.ring.destroy();
    await sibling.ring.destroy();
  }
});

for (const sharedManager of [true, false]) {
  const transport = sharedManager ? 'hardware manager' : 'Ledger host';
  test(`a refused browser receiver leaves the existing ${transport} connected and no usable controls`, async () => {
    const f = fixture();
    const host = createKeyringHost(f.storage, { deviceUnlock: f.port });
    let connected = false;
    let disconnects = 0;
    const ledger = {
      evm: {},
      utxo: {},
      async connect() {
        connected = true;
      },
      async disconnect() {
        disconnects++;
        connected = false;
      },
      getStatus: () => ({ connected }),
    };
    const hardwareManager = sharedManager
      ? new HardwareWalletManager(ledger)
      : undefined;
    const ledgerHost = sharedManager ? undefined : ledger;
    const owner = manager(host, true, hardwareManager, ledgerHost);
    let abandoned;
    try {
      await initialize(owner);
      if (hardwareManager) {
        await hardwareManager.ensureConnection(HardwareWalletType.LEDGER);
      } else {
        await owner.ring.ledgerSigner.ensureConnection();
      }
      assert.equal(connected, true);
      assert.throws(
        () =>
          new KeyringManager(host, {
            trezorHost: trezorHost(),
            captureEvmSubmission: () => {
              throw new Error('EVM submission is outside this fixture');
            },
            ...(ledgerHost ? { ledgerHost } : { hardwareManager }),
            receiveDeviceUnlock(value) {
              abandoned = value;
              if (sharedManager) throw new Error('fixture refused delivery');
              return Promise.reject(new Error('fixture returned a promise'));
            },
          }),
        sharedManager ? /fixture refused delivery/ : /complete synchronously/
      );
      const counts = f.counts();
      await assert.rejects(
        abandoned.resume(current),
        /unavailable|session changed|destroyed/
      );
      await assert.rejects(
        abandoned.issue(password, current),
        /unavailable|session changed|destroyed/
      );
      assert.deepEqual(f.counts(), counts);
      assert.equal(disconnects, 0);
      assert.equal(connected, true);
      assert.equal(owner.ring.isUnlocked(), true);
    } finally {
      await owner.ring.destroy();
    }
  });
}
