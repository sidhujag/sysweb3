import * as ecc from '@bitcoinerlab/secp256k1';
import * as syscoinjs from 'syscoinjs-lib';

import {
  createKeyringHost,
  INetworkType,
  KeyringAccountType,
  SoftwareKeyring,
} from '../../../src/software';
import { PsbtUtils } from '../../../src/utils/psbt';
import { parsePsbtAccountXpub } from '../../../src/utils/psbt-account-scope';

import type { KeyringStoragePort } from '../../../src/software';

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'public PSBT operation fixture';
const noop = () => undefined;
const actual = jest.requireActual('syscoinjs-lib');

async function fixture(policy: 'session' | 'operation' = 'operation') {
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
  const state: any = {
    activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
    activeNetwork: {
      kind: INetworkType.Syscoin,
      chainId: 57,
      slip44: 57,
      label: 'Syscoin',
      currency: 'sys',
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
  const ring = new SoftwareKeyring(createKeyringHost(storage), {
    captureEvmSubmission: null,
    secretLifetime: policy,
  });
  ring.setVaultStateGetter(() => state);
  state.accounts.HDAccount[0] = await ring.initializeWalletSecurely(
    mnemonic,
    password
  );
  const publicNode = parsePsbtAccountXpub(state.accounts.HDAccount[0].xpub);
  const publicKey = publicNode.derive(0).derive(0).publicKey;
  const payment = actual.utils.bitcoinjs.payments.p2wpkh({
    pubkey: publicKey,
    network: { ...actual.utils.bitcoinjs.networks.bitcoin, bech32: 'sys' },
  });
  const previous = new actual.utils.bitcoinjs.Transaction();
  previous.addInput(Buffer.alloc(32), 0xffffffff);
  previous.addOutput(payment.output, 100000n);
  const psbt = new actual.utils.bitcoinjs.Psbt();
  psbt.addInput({
    hash: previous.getId(),
    index: 0,
    nonWitnessUtxo: previous.toBuffer(),
    unknownKeyVals: [
      { key: Buffer.from('address'), value: Buffer.from(payment.address) },
    ],
  });
  psbt.addOutput({ script: payment.output, value: 99000n });
  const input = {
    ...PsbtUtils.toPali(psbt),
    assets: JSON.stringify([['123', { symbol: 'FIXTURE' }]]),
  };
  const requests = jest.fn(async () => {
    if (policy === 'operation') expect(ring.isUnlocked()).toBe(false);
    return {
      ok: true,
      json: async () => ({
        tokens: [{ name: payment.address, path: "m/84'/57'/0'/0/0" }],
      }),
    };
  });
  const read = {
    assertCurrent: noop,
    signal: new AbortController().signal,
    fetch: requests as unknown as typeof fetch,
  };
  const run = <T>(work: () => Promise<T>) =>
    ring.withSecretOperation(
      {
        async withSecret(check, consume) {
          check();
          await consume(password);
          check();
        },
      },
      { signal: read.signal, assertCurrent: noop },
      work
    );
  return { ring, state, psbt, input, requests, read, run };
}

beforeEach(() => {
  jest
    .spyOn(syscoinjs.utils.HDSigner.prototype, 'sign')
    .mockImplementation(actual.utils.HDSigner.prototype.sign);
  (syscoinjs.utils.fetchBackendAccount as jest.Mock).mockImplementation(
    actual.utils.fetchBackendAccount
  );
});
afterEach(() => {
  jest.restoreAllMocks();
});

it('prepares a path-less external PSBT publicly, then signs with no network under the secret lease', async () => {
  const f = await fixture();
  try {
    const prepared = await f.ring.syscoinTransaction.preparePSBTForSigning(
      { psbt: f.input },
      f.read
    );
    expect(f.requests).toHaveBeenCalledTimes(1);
    expect(f.ring.isUnlocked()).toBe(false);
    expect(
      PsbtUtils.fromPali(
        prepared,
        f.state.activeNetwork
      ).data.globalMap.unsignedTx.toBuffer()
    ).toEqual(f.psbt.data.globalMap.unsignedTx.toBuffer());
    expect(prepared.assets).toEqual(f.input.assets);
    const noNetwork = {
      ...f.read,
      fetch: jest.fn(async () => {
        throw new Error('network inside lease');
      }),
    };
    const signed = await f.run(() =>
      f.ring.syscoinTransaction.signPSBT({ psbt: prepared }, noNetwork)
    );
    expect(noNetwork.fetch).not.toHaveBeenCalled();
    expect(
      PsbtUtils.fromPali(signed, f.state.activeNetwork).extractTransaction()
        .ins[0].witness.length
    ).toBeGreaterThan(0);
    expect(f.ring.isUnlocked()).toBe(false);
    expect((f.ring as any).sessionMnemonic).toBeNull();
    expect((f.ring as any).sessionPassword).toBeNull();
  } finally {
    await f.ring.destroy();
  }
});

it('refuses unresolved paths under an operation lease without fetching or signing', async () => {
  const f = await fixture();
  try {
    const sign = jest.spyOn(syscoinjs.utils.HDSigner.prototype, 'sign');
    await expect(
      f.run(() => f.ring.syscoinTransaction.signPSBT({ psbt: f.input }, f.read))
    ).rejects.toThrow('outside the approved account');
    expect(f.requests).not.toHaveBeenCalled();
    expect(sign).not.toHaveBeenCalled();
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('refuses public enrichment requested from inside an operation lease', async () => {
  const f = await fixture();
  try {
    await expect(
      f.run(() =>
        f.ring.syscoinTransaction.preparePSBTForSigning(
          { psbt: f.input },
          f.read
        )
      )
    ).rejects.toThrow('before the secret operation');
    expect(f.requests).not.toHaveBeenCalled();
  } finally {
    await f.ring.destroy();
  }
});

it('rejects cancellation while public metadata is in flight', async () => {
  const f = await fixture();
  const controller = new AbortController();
  try {
    const read = {
      ...f.read,
      signal: controller.signal,
      fetch: (async () => {
        controller.abort();
        return { ok: true, json: async () => ({ tokens: [] }) };
      }) as typeof fetch,
    };
    await expect(
      f.ring.syscoinTransaction.preparePSBTForSigning({ psbt: f.input }, read)
    ).rejects.toThrow();
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('preserves session-policy implicit enrichment and real software signing', async () => {
  const f = await fixture('session');
  try {
    const signed = await f.ring.syscoinTransaction.signPSBT(
      { psbt: f.input },
      f.read
    );
    expect(f.requests).toHaveBeenCalledTimes(1);
    expect(
      PsbtUtils.fromPali(signed, f.state.activeNetwork).extractTransaction()
        .ins[0].witness.length
    ).toBeGreaterThan(0);
    expect(f.ring.isUnlocked()).toBe(true);
  } finally {
    await f.ring.destroy();
  }
});

it('rejects an untrusted path that does not own the spent output before signing', async () => {
  const f = await fixture();
  try {
    const read = {
      ...f.read,
      fetch: (async () => ({
        ok: true,
        json: async () => ({
          tokens: [
            {
              name: f.psbt.data.inputs[0].unknownKeyVals[0].value.toString(),
              path: "m/84'/57'/0'/0/9",
            },
          ],
        }),
      })) as typeof fetch,
    };
    await expect(
      f.ring.syscoinTransaction.preparePSBTForSigning({ psbt: f.input }, read)
    ).rejects.toThrow('outside the approved account');
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});

it('signs only the owned input of a publicly prepared PSBT with a hintless foreign input', async () => {
  const f = await fixture();
  try {
    const foreignKey = Buffer.from(
      '02' + '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
      'hex'
    );
    const foreign = actual.utils.bitcoinjs.payments.p2wpkh({
      pubkey: foreignKey,
    });
    const previous = new actual.utils.bitcoinjs.Transaction();
    previous.addInput(Buffer.alloc(32, 1), 0xffffffff);
    previous.addOutput(foreign.output, 100000n);
    f.psbt.addInput({
      hash: previous.getId(),
      index: 0,
      nonWitnessUtxo: previous.toBuffer(),
    });
    const input = { ...PsbtUtils.toPali(f.psbt), assets: f.input.assets };
    const prepared = await f.ring.syscoinTransaction.preparePSBTForSigning(
      { psbt: input },
      f.read
    );
    expect(f.requests).toHaveBeenCalledTimes(1);
    const noNetwork = {
      ...f.read,
      fetch: jest.fn(async () => {
        throw new Error('network inside lease');
      }),
    };
    const result = await f.run(() =>
      f.ring.syscoinTransaction.signPSBT({ psbt: prepared }, noNetwork)
    );
    const signed = PsbtUtils.fromPali(result, f.state.activeNetwork);
    const witness = Buffer.from(signed.data.inputs[0].finalScriptWitness);
    // This fixture has exactly the standard two short P2WPKH witness items.
    expect(witness[0]).toBe(2);
    const signature = witness.subarray(2, 2 + witness[1]);
    const keyOffset = 2 + witness[1];
    const publicKey = witness.subarray(keyOffset + 1);
    expect(publicKey.length).toBe(witness[keyOffset]);
    const verified = PsbtUtils.fromPali(prepared, f.state.activeNetwork);
    verified.updateInput(0, { partialSig: [{ signature, pubkey: publicKey }] });
    expect(
      verified.validateSignaturesOfInput(0, (key, hash, sig) =>
        ecc.verify(hash, key, sig)
      )
    ).toBe(true);
    expect(signed.data.inputs[1]).toEqual(
      PsbtUtils.fromPali(input, f.state.activeNetwork).data.inputs[1]
    );
    expect(signed.data.inputs[1].finalScriptWitness).toBeUndefined();
    expect(signed.data.inputs[1].partialSig).toBeUndefined();
    expect(signed.data.globalMap.unsignedTx.toBuffer()).toEqual(
      f.psbt.data.globalMap.unsignedTx.toBuffer()
    );
    expect(noNetwork.fetch).not.toHaveBeenCalled();
    expect(f.ring.isUnlocked()).toBe(false);
  } finally {
    await f.ring.destroy();
  }
});
