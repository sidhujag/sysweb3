// Reload the SDK after shared setup so its provider response normalizer stays
// real while every provider operation below remains an offline fixture.
jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };

jest.mock('../../../src/providers', () => ({
  ...jest.requireActual('../../../src/providers'),
  CustomJsonRpcProvider: jest.fn(),
}));

import ecc from '@bitcoinerlab/secp256k1';
import CryptoJS from 'crypto-js';
import { Transaction } from 'ethers/transaction';
import { HDNodeWallet, Wallet } from 'ethers/wallet';

import { BigNumber } from '../../../src/ethers-v6';
import { KeyringCore } from '../../../src/keyring-core';
import {
  createKeyringHost,
  prepareKeyringHost,
} from '../../../src/keyring-host';
import { INetworkType, KeyringAccountType } from '../../../src/software';
import { admitTestSignedDispatch } from '../../helpers/evm-submission';

import type {
  KeyringStoragePort,
  SecretOperationCredentialPort,
} from '../../../src/software';

const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'offline effective signer lifetime fixture';
const importedWallet = new Wallet(`0x${'11'.repeat(32)}`);
const hdWallet = HDNodeWallet.fromPhrase(phrase);
const recipient = `0x${'33'.repeat(20)}`;
const noop = () => undefined;
const credential: SecretOperationCredentialPort = {
  async withSecret(check, consume) {
    check();
    await consume(password);
    check();
  },
};
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((finish) => (resolve = finish));
  return { promise, resolve };
};

async function fixture(
  selectedType: KeyringAccountType.Ledger | KeyringAccountType.Trezor,
  targetType: KeyringAccountType.HDAccount | KeyringAccountType.Imported
) {
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
  const persistSigned = jest.fn(async () => undefined);
  const { binding } = prepareKeyringHost(createKeyringHost(storage), {
    secretLifetime: 'operation',
    captureEvmSubmission: () => ({
      assertCurrent: noop,
      persistSigned,
      dispatchSigned: admitTestSignedDispatch,
    }),
  });
  // These ports are deliberately unusable: every transaction below must route
  // to the real software target, never to the selected hardware account.
  const ring = new KeyringCore(binding, {
    ledgerSigner: {} as never,
    trezorSigner: {} as never,
    syscoinHardwareSigners: {},
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
  const options = { signal: new AbortController().signal, assertCurrent: noop };
  state.accounts.Imported[0] = await ring.withSecretOperation(
    credential,
    options,
    () => ring.importAccount(importedWallet.privateKey)
  );
  const target = state.accounts[targetType][0];
  const wallet =
    targetType === KeyringAccountType.Imported ? importedWallet : hdWallet;
  expect(target.address.toLowerCase()).toBe(wallet.address.toLowerCase());
  state.accounts[selectedType][0] = {
    address: `0x${'22'.repeat(20)}`,
    xpub: 'public hardware identity',
  };
  state.activeAccount = { id: 0, type: selectedType };
  const unsigned = {
    chainId: 1,
    type: 0,
    nonce: 0,
    to: recipient,
    value: 7,
    gasLimit: 21000,
    gasPrice: 100,
    data: '0x',
  };
  const original = Transaction.from(unsigned);
  original.signature = wallet.signingKey.sign(original.unsignedHash);
  const originalResponse = {
    hash: original.hash!,
    from: original.from!,
    to: original.to,
    nonce: original.nonce,
    type: original.type,
    chainId: 1,
    signature: original.signature,
    data: original.data,
    value: BigNumber.from(original.value),
    gasLimit: BigNumber.from(original.gasLimit),
    gasPrice: BigNumber.from(original.gasPrice!),
    maxFeePerGas: null,
    maxPriorityFeePerGas: null,
  };
  const provider = {
    verifyConfiguredChainId: jest.fn(async () => undefined),
    getNetwork: jest.fn(async () => ({ chainId: 1 })),
    getTransaction: jest.fn(async () => originalResponse),
    getTransactionCount: jest.fn(async () => 0),
    getTransactionReceipt: jest.fn(async () => null),
    getBalance: jest.fn(async () => BigNumber.from('1000000000000000000')),
    getBlock: jest.fn(async () => ({
      number: 8,
      gasLimit: BigNumber.from(30000000),
      baseFeePerGas: null,
    })),
    getGasPrice: jest.fn(async () => BigNumber.from(100)),
    estimateGas: jest.fn(async () => BigNumber.from(21000)),
    sendTransaction: jest.fn(async (raw: string) => {
      const tx = Transaction.from(raw);
      return { hash: tx.hash!, from: tx.from!, nonce: tx.nonce, chainId: 1 };
    }),
  };
  Object.defineProperty(ring.ethereumTransaction, 'web3Provider', {
    configurable: true,
    get: () => provider,
  });
  const selectedIdentity = {
    id: 0,
    type: selectedType,
    expectedAddress: state.accounts[selectedType][0].address,
  };
  const targetIdentity = {
    id: 0,
    type: targetType,
    expectedAddress: target.address,
  };
  const admission = {
    targetAccount: { id: 0, type: targetType },
    approvedMaximumFee: '10000000',
    assertCurrentContext: noop,
    validateOriginal: noop,
  };
  const submit = (kind: 'send' | 'cancel' | 'speed-up') => {
    if (kind === 'cancel')
      return ring.ethereumTransaction.cancelSentTransaction(
        original.hash!,
        true,
        undefined,
        admission
      );
    if (kind === 'speed-up')
      return ring.ethereumTransaction.sendTransactionWithEditedFee(
        original.hash!,
        true,
        admission
      );
    return ring.ethereumTransaction.sendFormattedTransaction(unsigned, true, {
      mode: 'specialized',
      assertCurrent: noop,
      selectedAccount: selectedIdentity,
      targetAccount: targetIdentity,
    });
  };
  return { ring, state, target, provider, persistSigned, submit };
}

afterEach(() => jest.restoreAllMocks());

for (const hardware of [
  KeyringAccountType.Ledger,
  KeyringAccountType.Trezor,
] as const) {
  for (const software of [
    KeyringAccountType.HDAccount,
    KeyringAccountType.Imported,
  ] as const) {
    it.each(['send', 'cancel', 'speed-up'] as const)(
      `${hardware} selection cannot let ${software} %s outlive its secret operation`,
      async (kind) => {
        const f = await fixture(hardware, software);
        const entered = deferred(),
          release = deferred();
        let extracted = false;
        const decrypt = CryptoJS.AES.decrypt;
        jest
          .spyOn(CryptoJS.AES, 'decrypt')
          .mockImplementation((cipher, key, config) => {
            const result = decrypt(cipher, key, config);
            if (cipher === f.target.xprv) extracted = true;
            return result;
          });
        f.provider.verifyConfiguredChainId.mockImplementation(async () => {
          if (extracted) {
            entered.resolve();
            await release.promise;
          }
        });
        const sign = jest.spyOn(ecc, 'signRecoverable');
        const controller = new AbortController();
        const pending = f.ring.withSecretOperation(
          credential,
          { signal: controller.signal, assertCurrent: noop },
          () => f.submit(kind)
        );
        const outcome = pending.then(
          (value) => ({ value }),
          (error) => ({ error })
        );
        try {
          await Promise.race([
            entered.promise,
            outcome.then((result) => {
              throw new Error(
                `Signing finished before the held RPC: ${JSON.stringify(
                  result
                )}`
              );
            }),
          ]);
          expect(extracted).toBe(true);
          controller.abort();
          expect(f.ring.hasPublicSession()).toBe(true);
          expect(f.ring.isUnlocked()).toBe(false);
          release.resolve();
          expect(await outcome).toHaveProperty('error');
          expect({
            signatures: sign.mock.calls.length,
            journalWrites: f.persistSigned.mock.calls.length,
            broadcasts: f.provider.sendTransaction.mock.calls.length,
          }).toEqual({ signatures: 0, journalWrites: 0, broadcasts: 0 });
        } finally {
          release.resolve();
          await outcome;
          await f.ring.destroy();
        }
      }
    );

    it(`${hardware} selection preserves a live ${software} software send`, async () => {
      const f = await fixture(hardware, software);
      const sign = jest.spyOn(ecc, 'signRecoverable');
      try {
        const result = await f.ring.withSecretOperation(
          credential,
          { signal: new AbortController().signal, assertCurrent: noop },
          () => f.submit('send')
        );
        expect(result).toMatchObject({ from: f.target.address });
        expect(sign).toHaveBeenCalledTimes(1);
        expect(f.persistSigned).toHaveBeenCalledTimes(1);
        expect(f.provider.sendTransaction).toHaveBeenCalledTimes(1);
        expect(f.ring.isUnlocked()).toBe(false);
      } finally {
        await f.ring.destroy();
      }
    });
  }

  it(`${hardware} public signing context needs no software secret operation and still binds its network`, async () => {
    const f = await fixture(hardware, KeyringAccountType.HDAccount);
    try {
      expect(f.ring.isUnlocked()).toBe(false);
      expect(f.ring.hasPublicSession()).toBe(true);
      const context = (
        f.ring.ethereumTransaction as any
      ).captureEvmSigningContext();
      expect(() => context.assertCurrent()).not.toThrow();
      f.state.activeNetwork = {
        ...f.state.activeNetwork,
        url: 'https://different.invalid',
      };
      expect(() => context.assertCurrent()).toThrow('context changed');
      expect(f.persistSigned).not.toHaveBeenCalled();
      expect(f.provider.sendTransaction).not.toHaveBeenCalled();
    } finally {
      await f.ring.destroy();
    }
  });
}
