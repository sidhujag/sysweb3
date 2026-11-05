jest.resetModules();
jest.unmock('syscoinjs-lib');
if ((global as any).window)
  (global as any).window.location = { href: 'http://localhost/' };

import * as syscoinjs from 'syscoinjs-lib';

import {
  INetworkType,
  KeyringAccountType,
  SoftwareKeyring,
  createKeyringHost,
} from '../../../src/software';
import {
  readPublicSyscoinFee,
  SyscoinTransactionsCore,
} from '../../../src/transactions/syscoin-core';
import { PsbtUtils } from '../../../src/utils/psbt';

import type { KeyringStoragePort } from '../../../src/software';

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const endpoint = 'https://offline.invalid/wallet/';
const base = endpoint.slice(0, -1);
const feeUrl = `${base}/api/v2/estimatefee/1`;
const network = syscoinjs.utils.syscoinNetworks.testnet;
const bitcoin = syscoinjs.utils.bitcoinjs;
const receive = bitcoin.payments.p2wpkh({
  hash: Buffer.alloc(20, 2),
  network,
}).address;
const request = { amount: '0.0004', receivingAddress: receive };
const hd = KeyringAccountType.HDAccount;
const imported = KeyringAccountType.Imported;
const rings: SoftwareKeyring[] = [];

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

async function fixture() {
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
      for (const [key, value] of Object.entries(items)) records.set(key, value);
      return true;
    },
  };
  const state = {
    activeAccount: { id: 0, type: hd as KeyringAccountType },
    activeNetwork: {
      kind: INetworkType.Syscoin,
      chainId: 5700,
      slip44: 1,
      label: 'Syscoin Testnet',
      currency: 'tsys',
      url: endpoint,
    },
    accounts: {
      HDAccount: {},
      Imported: {},
      Ledger: {},
      Trezor: {},
      SmartAccount: {},
    },
  };
  const host = createKeyringHost(storage);
  const ring = new SoftwareKeyring(host, { captureEvmSubmission: null });
  rings.push(ring);
  ring.setVaultStateGetter(() => state);
  const account = await ring.initializeWalletSecurely(
    mnemonic,
    'synthetic test password'
  );
  state.accounts.HDAccount[0] = account;
  return { ring, state, account, host };
}

function owned(
  reply: (url: string) => Promise<Response> | Response,
  assertCurrent = () => undefined
) {
  const control = new AbortController();
  const calls: string[] = [];
  const options = {
    signal: control.signal,
    assertCurrent,
    fetch: jest.fn<
      ReturnType<typeof globalThis.fetch>,
      Parameters<typeof globalThis.fetch>
    >(async (input, init) => {
      expect(init?.method).toBe('GET');
      expect(init?.signal).toBe(control.signal);
      const url = String(input);
      calls.push(url);
      return reply(url);
    }),
  };
  return { control, calls, options };
}

const parent = (value: number) => value.toString(16).padStart(64, '0');
const witness = (address: string, n = 1) => ({
  txid: parent(n),
  vout: 0,
  value: '100000',
  address,
  confirmations: 10,
  path: "m/84'/1'/0'/0/0",
});
const accountRoute = (xpub: string) =>
  `${base}/api/v2/xpub/${xpub}?tokens=used&details=tokens`;
const fundingRoute = (identifier: string) =>
  `${base}/api/v2/utxo/${identifier}`;
const fee = () => Response.json({ result: '0.00001024' });

beforeEach(() => {
  jest
    .spyOn(globalThis, 'fetch')
    .mockClear()
    .mockRejectedValue(new Error('Ambient HTTP is forbidden'));
});

afterEach(async () => {
  await Promise.all(rings.splice(0).map((ring) => ring.destroy()));
  jest.restoreAllMocks();
});

it('requires ownership and routes real legacy PSBT fee, funding and prevout through one scoped GET transport', async () => {
  const { ring, state } = await fixture();
  const signer = bitcoin.ECPair.fromPrivateKey(Buffer.alloc(32, 1), {
    network,
  });
  const legacy = bitcoin.payments.p2pkh({ pubkey: signer.publicKey, network });
  const account = await ring.importAccount(signer.toWIF(), undefined, {
    utxoAddressType: 'p2pkh',
  });
  expect(account.address).toBe(legacy.address);
  expect(account.xpub).toBe(legacy.address);
  state.accounts.Imported[account.id] = account;
  state.activeAccount = { id: account.id, type: imported };
  const previous = new bitcoin.Transaction();
  previous.addInput(Buffer.alloc(32, 7), 0);
  previous.addOutput(legacy.output, 100000n);
  const txid = previous.getId();
  const route = fundingRoute(account.address);
  const rawUrl = `${base}/api/v2/tx/${txid}`;
  let advertised = 100000;
  const reply = (url: string) => {
    if (url === feeUrl) return fee();
    if (url === route)
      return Response.json([
        {
          txid,
          vout: 0,
          value: String(advertised),
          address: account.address,
          confirmations: 10,
        },
      ]);
    if (url === rawUrl) return Response.json({ hex: previous.toHex() });
    throw new Error('Unexpected route');
  };
  const ambient = jest.mocked(globalThis.fetch);
  await expect(
    Reflect.apply(
      ring.syscoinTransaction.getEstimateSysTransactionFee,
      undefined,
      [request]
    )
  ).rejects.toMatchObject({
    code: 'TRANSACTION_CREATION_FAILED',
    message: 'Missing owned UTXO read',
  });
  expect(ambient).not.toHaveBeenCalled();

  const transport = owned(reply);
  const quote = await ring.syscoinTransaction.getEstimateSysTransactionFee(
    request,
    transport.options
  );
  expect(transport.calls).toEqual([feeUrl, route, rawUrl]);
  const psbt = PsbtUtils.fromPali(quote.psbt, state.activeNetwork);
  expect(Buffer.from(psbt.data.inputs[0].nonWitnessUtxo!).toString('hex')).toBe(
    previous.toHex()
  );
  expect(psbt.data.inputs[0].finalScriptSig).toBeUndefined();
  expect(ambient).not.toHaveBeenCalled();

  advertised = 70000;
  const dishonest = owned(reply);
  await expect(
    ring.syscoinTransaction.getEstimateSysTransactionFee(
      { ...request, feeRate: 0.00000002 },
      dishonest.options
    )
  ).rejects.toMatchObject({
    message: 'Mismatched owned legacy previous transaction value',
  });
  expect(dishonest.calls).toEqual([route, rawUrl]);
  expect(ambient).not.toHaveBeenCalled();
});

it('uses the SDK change-address lookup and the originally captured exclusions after a held fee', async () => {
  const { ring, state, account } = await fixture();
  const accountReply = () =>
    Response.json({ tokens: [{ transfers: 2, path: "m/84'/1'/0'/1/0" }] });
  const ambient = jest.mocked(globalThis.fetch);
  const readChange = owned((url) => {
    expect(String(url)).toBe(accountRoute(account.xpub));
    return accountReply();
  });
  const change = await ring.getAddress(account.xpub, true, readChange.options);
  expect(readChange.calls).toEqual([accountRoute(account.xpub)]);
  expect(ambient).not.toHaveBeenCalled();
  const feeStarted = deferred();
  const release = deferred();
  const excludedOutpoints = [{ txid: parent(1), vout: 0 }];
  const txOptions = {
    memoHeader: Buffer.from('ab', 'hex'),
    memo: Buffer.from('cd', 'hex'),
  };
  const transport = owned(async (url) => {
    if (url === feeUrl) {
      feeStarted.resolve();
      await release.promise;
      return fee();
    }
    if (url === accountRoute(account.xpub)) return accountReply();
    if (url === fundingRoute(account.xpub))
      return Response.json([
        witness(account.address),
        witness(account.address, 2),
      ]);
    throw new Error('Unexpected route');
  });
  const pending = ring.syscoinTransaction.getEstimateSysTransactionFee(
    { ...request, excludedOutpoints, txOptions },
    transport.options
  );
  await Promise.race([feeStarted.promise, pending]);
  excludedOutpoints[0].txid = parent(2);
  txOptions.memo.fill(0xff);
  transport.options.fetch = jest
    .fn()
    .mockRejectedValue(new Error('Replaced transport must not run'));
  release.resolve();
  const quote = await pending;
  const psbt = PsbtUtils.fromPali(quote.psbt, state.activeNetwork);
  expect(transport.calls).toEqual([
    feeUrl,
    accountRoute(account.xpub),
    fundingRoute(account.xpub),
  ]);
  expect(psbt.txInputs).toHaveLength(1);
  expect(Buffer.from(psbt.txInputs[0].hash).reverse().toString('hex')).toBe(
    parent(2)
  );
  expect(psbt.txOutputs.map((output) => output.address)).toContain(change);
  expect(
    psbt.txOutputs.some(
      (output) => Buffer.from(output.script).toString('hex') === '6a02abcd'
    )
  ).toBe(true);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('rejects absent ownership and a nonselected ID or xpub before any address read', async () => {
  const { ring, account } = await fixture();
  const ambient = jest.mocked(globalThis.fetch);
  ambient.mockResolvedValueOnce(Response.json({ tokens: [] }));
  const read = owned(() => Response.json({ tokens: [] }));
  await expect(
    Reflect.apply(ring.getAddress, undefined, [account.xpub, true])
  ).rejects.toThrow('Missing owned UTXO read');
  await expect(ring.getChangeAddress(1, read.options)).rejects.toThrow(
    'UTXO account is not active'
  );
  await expect(
    ring.getAddress('another-xpub', true, read.options)
  ).rejects.toThrow('UTXO account is not active');
  expect(ambient).not.toHaveBeenCalled();
  expect(read.calls).toEqual([]);
});

it('discards address, pubkey and path results if the SDK wallet locks during body parsing', async () => {
  const { ring, account } = await fixture();
  const parsing = deferred();
  const release = deferred();
  let entered = 0;
  const read = owned(() => {
    const response = Response.json({ tokens: [] });
    jest.spyOn(response, 'json').mockImplementation(async () => {
      if (++entered === 3) parsing.resolve();
      await release.promise;
      return { tokens: [] };
    });
    return response;
  });
  const pending = Promise.allSettled([
    ring.updateReceivingAddress(read.options),
    ring.getPubkey(account.id, false, read.options),
    ring.getBip32Path(account.id, true, read.options),
  ]);
  await Promise.race([parsing.promise, pending]);
  await ring.lockWallet();
  release.resolve();
  for (const result of await pending)
    expect(result).toMatchObject({
      status: 'rejected',
      reason: expect.objectContaining({
        message: 'Wallet signing context changed',
      }),
    });
  expect(read.calls).toEqual(Array(3).fill(accountRoute(account.xpub)));
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('keeps the original asset funding policy when a Map is changed during a fee read', async () => {
  const { ring, state, account } = await fixture();
  const feeStarted = deferred();
  const release = deferred();
  const assetGuid = '123';
  const assetWhiteList = new Map<string, boolean>();
  const transport = owned(async (url) => {
    if (url === feeUrl) {
      feeStarted.resolve();
      await release.promise;
      return fee();
    }
    if (url === accountRoute(account.xpub))
      return Response.json({ tokens: [] });
    if (url === fundingRoute(account.xpub))
      return Response.json([
        {
          ...witness(account.address),
          assetInfo: { assetGuid, value: '1' },
        },
      ]);
    throw new Error('Unexpected route');
  });
  const params = { ...request, txOptions: { assetWhiteList } };
  const pending = ring.syscoinTransaction.getEstimateSysTransactionFee(
    params,
    transport.options
  );
  await Promise.race([feeStarted.promise, pending]);
  assetWhiteList.set(assetGuid, true);
  release.resolve();
  await expect(pending).rejects.toMatchObject({ error: true });

  // A fresh quote can use the same input when it starts with explicit consent.
  const quote = await ring.syscoinTransaction.getEstimateSysTransactionFee(
    params,
    transport.options
  );
  const psbt = PsbtUtils.fromPali(quote.psbt, state.activeNetwork);
  expect(psbt.txInputs).toHaveLength(1);
  expect(Buffer.from(psbt.txInputs[0].hash).reverse().toString('hex')).toBe(
    parent(1)
  );
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('keeps identical account lookups independently owned and builds MAX from one funding snapshot', async () => {
  const first = await fixture();
  const second = await fixture();
  expect(first.account.xpub).toBe(second.account.xpub);
  const xpub = first.account.xpub;
  const started = deferred();
  const release = deferred();
  const one = owned(async (url) => {
    expect(url).toBe(accountRoute(xpub));
    started.resolve();
    await release.promise;
    return Response.json({ tokens: [] });
  });
  const two = owned((url) => {
    if (url === accountRoute(xpub)) return Response.json({ tokens: [] });
    if (url === fundingRoute(xpub))
      return Response.json([
        witness(second.account.address),
        witness(second.account.address, 2),
      ]);
    throw new Error('Unexpected route');
  });
  const fixedFee = { ...request, feeRate: 0.00000001 };
  const cancelled = first.ring.syscoinTransaction.getEstimateSysTransactionFee(
    fixedFee,
    one.options
  );
  await Promise.race([started.promise, cancelled]);
  try {
    const max =
      await second.ring.syscoinTransaction.getEstimateSysTransactionFee(
        { ...fixedFee, isMax: true, nativeSweep: true, token: null },
        two.options
      );
    const psbt = PsbtUtils.fromPali(max.psbt, second.state.activeNetwork);
    expect(max.grossAmount).toBe('0.002');
    expect(psbt.txInputs).toHaveLength(2);
    expect(psbt.txOutputs).toHaveLength(1);
    expect(psbt.txOutputs[0].address).toBe(receive);
    expect(two.calls).toEqual([accountRoute(xpub), fundingRoute(xpub)]);
  } finally {
    one.control.abort();
    release.resolve();
    await expect(cancelled).rejects.toMatchObject({
      code: 'TRANSACTION_CREATION_FAILED',
    });
  }
  expect(one.calls).toEqual([accountRoute(xpub)]);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it.each(['lock', 'network', 'network ABA', 'response body lock'])(
  'refuses subsequent reads or a PSBT after %s during the first response',
  async (revocation) => {
    const { ring, state } = await fixture();
    let epoch = 0;
    const read = owned(
      async (url) => {
        expect(url).toBe(feeUrl);
        if (revocation === 'lock') await ring.lockWallet();
        if (revocation === 'network') state.activeNetwork.currency = 'btc';
        if (revocation === 'network ABA') {
          const previous = state.activeNetwork.url;
          state.activeNetwork.url = 'https://other.invalid/';
          epoch++;
          state.activeNetwork.url = previous;
          epoch++;
        }
        if (revocation === 'response body lock') {
          const response = fee();
          const json = response.json.bind(response);
          response.json = async () => {
            await ring.lockWallet();
            return json();
          };
          return response;
        }
        return fee();
      },
      () => {
        if (epoch !== 0) throw new Error('Host selection changed');
      }
    );
    await expect(
      ring.syscoinTransaction.getEstimateSysTransactionFee(
        request,
        read.options
      )
    ).rejects.toMatchObject({ code: 'TRANSACTION_CREATION_FAILED' });
    expect(read.calls).toEqual([feeUrl]);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  }
);

it('revokes a held fee after a real software session is transferred away and back', async () => {
  const { ring, state, account, host } = await fixture();
  const sibling = new SoftwareKeyring(host, { captureEvmSubmission: null });
  sibling.setVaultStateGetter(() => state);
  rings.push(sibling);
  const started = deferred();
  const release = deferred();
  const read = owned(async (url) => {
    if (url === feeUrl) {
      started.resolve();
      await release.promise;
      return fee();
    }
    if (url === accountRoute(account.xpub))
      return Response.json({ tokens: [] });
    if (url === fundingRoute(account.xpub))
      return Response.json([witness(account.address)]);
    throw new Error('Unexpected route');
  });
  const pending = ring.syscoinTransaction.getEstimateSysTransactionFee(
    request,
    read.options
  );
  await Promise.race([started.promise, pending]);
  try {
    const session = (ring as any).sessionPassword;
    ring.transferSessionTo(sibling);
    expect(ring.isUnlocked()).toBe(false);
    expect(sibling.isUnlocked()).toBe(true);
    sibling.transferSessionTo(ring);
    expect(ring.isUnlocked()).toBe(true);
    expect(sibling.isUnlocked()).toBe(false);
    expect((ring as any).sessionPassword).toBe(session);
  } finally {
    release.resolve();
  }
  await expect(pending).rejects.toMatchObject({
    code: 'TRANSACTION_CREATION_FAILED',
  });
  expect(read.calls).toEqual([feeUrl]);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('requires scoped fee reads, separates public fee, and refuses async guards or wrong endpoints', async () => {
  const { ring } = await fixture();
  const ambient = jest.mocked(globalThis.fetch);
  await expect(
    Reflect.apply(ring.syscoinTransaction.getRecommendedFee, undefined, [
      endpoint,
    ])
  ).rejects.toThrow('Missing owned UTXO read');
  const read = owned(() => Response.json({ result: '0.00002048' }));
  await expect(
    ring.syscoinTransaction.getRecommendedFee(endpoint, read.options)
  ).resolves.toBe(0.00000002);
  expect(read.calls).toEqual([feeUrl]);
  await expect(
    ring.syscoinTransaction.getRecommendedFee(endpoint, {
      ...read.options,
      async assertCurrent() {
        throw new Error('Asynchronous guard');
      },
    })
  ).rejects.toThrow('synchronous guard');
  await expect(
    ring.syscoinTransaction.getRecommendedFee(
      'https://other.invalid/',
      read.options
    )
  ).rejects.toThrow('endpoint changed');
  expect(read.calls).toEqual([feeUrl]);
  await ring.lockWallet();
  const publicRead = owned(() => fee());
  await expect(
    readPublicSyscoinFee(endpoint, publicRead.options)
  ).resolves.toBe(0.00000001);
  expect(publicRead.calls).toEqual([feeUrl]);
  expect(ambient).not.toHaveBeenCalled();
});

it('refuses owned preparation through an unscoped legacy builder', async () => {
  const { state } = await fixture();
  const read = owned(() => fee());
  const legacy = new SyscoinTransactionsCore(
    jest.fn(),
    () => ({ main: new syscoinjs.SyscoinJSLib(null, endpoint, network) }),
    () => ({
      accounts: state.accounts,
      activeAccountId: state.activeAccount.id,
      activeAccountType: state.activeAccount.type,
      activeNetwork: state.activeNetwork,
    }),
    {},
    () => () => undefined
  );
  const outcome = await legacy
    .getEstimateSysTransactionFee(
      { ...request, feeRate: 0.00000001 },
      read.options
    )
    .catch((error) => error);
  expect(globalThis.fetch).not.toHaveBeenCalled();
  expect(read.calls).toEqual([]);
  expect(outcome).toMatchObject({
    code: 'TRANSACTION_CREATION_FAILED',
    message: 'Owned UTXO read adapter is unavailable',
  });
});

async function missingPathPreparation() {
  const selected = await fixture();
  const { ring, account, state } = selected;
  const accountReply = () =>
    Response.json({
      tokens: [
        { name: account.address, transfers: 2, path: "m/84'/1'/0'/0/0" },
      ],
    });
  const transport = owned((url) => {
    if (url === feeUrl) return fee();
    if (url === accountRoute(account.xpub)) return accountReply();
    if (url === fundingRoute(account.xpub)) {
      return Response.json([{ ...witness(account.address), path: undefined }]);
    }
    throw new Error('Unexpected route');
  });
  const quote = await ring.syscoinTransaction.getEstimateSysTransactionFee(
    request,
    transport.options
  );
  const parsed = PsbtUtils.fromPali(quote.psbt, state.activeNetwork);
  expect(
    parsed.data.inputs[0].unknownKeyVals?.some(
      (pair) => Buffer.from(pair.key).toString() === 'path'
    )
  ).toBe(false);
  return { ...selected, quote, accountReply };
}

it('requires an owner and uses the original software missing-path signer through scoped xpub reads', async () => {
  const { ring, state, account, quote, accountReply } =
    await missingPathPreparation();
  const ambient = jest.mocked(globalThis.fetch);
  await expect(
    Reflect.apply(ring.syscoinTransaction.signPSBT, undefined, [
      { psbt: quote.psbt },
    ])
  ).rejects.toThrow('Missing owned UTXO read');
  expect(ambient).not.toHaveBeenCalled();

  const transport = owned(() => accountReply());
  const signed = await Reflect.apply(
    ring.syscoinTransaction.signPSBT,
    undefined,
    [{ psbt: quote.psbt }, transport.options]
  );
  const psbt = PsbtUtils.fromPali(signed, state.activeNetwork);
  expect(psbt.extractTransaction().ins[0].witness).toHaveLength(2);
  expect(psbt.data.globalMap.unsignedTx.toBuffer()).toEqual(
    PsbtUtils.fromPali(
      quote.psbt,
      state.activeNetwork
    ).data.globalMap.unsignedTx.toBuffer()
  );
  expect(transport.calls).toEqual([accountRoute(account.xpub)]);
  expect(ambient).not.toHaveBeenCalled();
});

it('rejects a failed owned missing-path read without ambient fallback or partial output', async () => {
  const { ring, account, quote } = await missingPathPreparation();
  const failure = new Error('Scoped path unavailable');
  const transport = owned(async () => {
    throw failure;
  });
  await expect(
    Reflect.apply(ring.syscoinTransaction.signPSBT, undefined, [
      { psbt: quote.psbt },
      transport.options,
    ])
  ).rejects.toBe(failure);
  expect(transport.calls).toEqual([accountRoute(account.xpub)]);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('rejects a held owned missing-path signature after actual keyring ownership ABA', async () => {
  const { ring, state, account, host, quote, accountReply } =
    await missingPathPreparation();
  const sibling = new SoftwareKeyring(host, { captureEvmSubmission: null });
  rings.push(sibling);
  sibling.setVaultStateGetter(() => state);
  const started = deferred();
  const release = deferred();
  const transport = owned(async () => {
    started.resolve();
    await release.promise;
    return accountReply();
  });
  const signing = Reflect.apply(ring.syscoinTransaction.signPSBT, undefined, [
    { psbt: quote.psbt },
    transport.options,
  ]);
  const checked = expect(signing).rejects.toThrow(
    'Wallet signing context changed'
  );
  try {
    await Promise.race([started.promise, signing]);
    ring.transferSessionTo(sibling);
    sibling.transferSessionTo(ring);
  } finally {
    release.resolve();
    await checked;
  }
  expect(transport.calls).toEqual([accountRoute(account.xpub)]);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

async function signedOwnedFixture() {
  const { ring, state, quote, accountReply } = await missingPathPreparation();
  const transport = owned(accountReply);
  const signed = await ring.syscoinTransaction.signPSBT(
    { psbt: quote.psbt },
    transport.options
  );
  const transaction = PsbtUtils.fromPali(
    signed,
    state.activeNetwork
  ).extractTransaction();
  return { ring, state, raw: transaction.toHex(), txid: transaction.getId() };
}

const submitUrl = `${base}/api/v2/sendtx/`;

function acknowledgment(txid: string): Response {
  const response = Response.json({ result: txid });
  Object.defineProperty(response, 'url', { value: submitUrl });
  return response;
}

it('refuses an omitted owner and old PSBT argument before ambient dispatch', async () => {
  const { ring, state, raw } = await signedOwnedFixture();
  const signed = PsbtUtils.toPali(
    PsbtUtils.fromPali(
      {
        psbt: new bitcoin.Psbt().toBase64(),
        assets: '[]',
      },
      state.activeNetwork
    )
  );
  for (const value of [raw, signed]) {
    await expect(
      Reflect.apply(ring.syscoinTransaction.sendTransaction, undefined, [value])
    ).rejects.toMatchObject({
      code: 'UTXO_SUBMISSION_NOT_DISPATCHED',
      transactionNotBroadcast: true,
    });
  }
  const fetch = jest.fn();
  await expect(
    Reflect.apply(ring.syscoinTransaction.sendTransaction, undefined, [
      raw,
      {
        assertCurrent: () => undefined,
        fetch,
        signal: new AbortController().signal,
      },
    ])
  ).rejects.toMatchObject({
    code: 'UTXO_SUBMISSION_NOT_DISPATCHED',
    transactionNotBroadcast: true,
  });
  expect(fetch).not.toHaveBeenCalled();
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('dispatches only after the captured descriptor is admitted, and preserves an ACK across a later selection change', async () => {
  const { ring, state, raw, txid } = await signedOwnedFixture();
  const hold = deferred();
  const admitted = deferred();
  const fetch = jest.fn(async () => {
    state.activeNetwork.url = 'https://other.invalid';
    return acknowledgment(txid);
  });
  const signal = new AbortController().signal;
  const pending = ring.syscoinTransaction.sendTransaction(raw, {
    signal,
    fetch,
    assertCurrent: () => undefined,
    async prepare(descriptor) {
      expect(Object.isFrozen(descriptor)).toBe(true);
      expect(descriptor).toEqual({ url: submitUrl, rawTransaction: raw, txid });
      admitted.resolve();
      await hold.promise;
    },
  });
  await Promise.race([admitted.promise, pending]);
  expect(fetch).not.toHaveBeenCalled();
  hold.resolve();
  await expect(pending).resolves.toEqual({ txid });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(fetch).toHaveBeenCalledWith(
    submitUrl,
    expect.objectContaining({ method: 'POST', body: raw, signal })
  );
  expect(globalThis.fetch).not.toHaveBeenCalled();
});

it('classifies lost authority before POST separately from a lost acknowledgment after dispatch', async () => {
  const { ring, state, raw, txid } = await signedOwnedFixture();
  const fetch = jest.fn().mockRejectedValue(new Error('Response lost'));
  const signal = new AbortController().signal;
  await expect(
    ring.syscoinTransaction.sendTransaction(raw, {
      signal,
      fetch,
      assertCurrent: () => undefined,
      async prepare() {
        state.activeNetwork.url = 'https://other.invalid';
      },
    })
  ).rejects.toMatchObject({
    code: 'UTXO_SUBMISSION_NOT_DISPATCHED',
    transactionNotBroadcast: true,
    txid,
  });
  expect(fetch).not.toHaveBeenCalled();
  state.activeNetwork.url = endpoint;
  await expect(
    ring.syscoinTransaction.sendTransaction(raw, {
      signal,
      fetch,
      assertCurrent: () => undefined,
      async prepare() {
        return undefined;
      },
    })
  ).rejects.toMatchObject({
    code: 'UTXO_SUBMISSION_UNKNOWN',
    transactionNotBroadcast: false,
    txid,
  });
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(globalThis.fetch).not.toHaveBeenCalled();
});
