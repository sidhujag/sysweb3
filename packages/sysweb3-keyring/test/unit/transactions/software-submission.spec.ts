import { Transaction } from 'ethers';

import { BigNumber } from '../../../src/ethers-v6';
import {
  SoftwareKeyring,
  createKeyringHost,
  KeyringAccountType,
  INetworkType,
} from '../../../src/software';

import type { EvmSignedSubmission } from '../../../src/transactions/evm-submission';
const phrase =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'Public SDK submission fixture 1!';
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

it.each(['healthy', 'lock', 'account-change'] as const)(
  'real SoftwareKeyring host enforces %s at its persisted-signature boundary',
  async (mode) => {
    const entered = deferred(),
      ack = deferred(),
      records = new Map<string, unknown>();
    let saved!: EvmSignedSubmission;
    const storage = {
      async get(key: string) {
        return records.get(key);
      },
      async set(key: string, value: unknown) {
        records.set(key, value);
      },
      async deleteItem(key: string) {
        records.delete(key);
      },
      async createManyIfAbsent(values: Record<string, unknown>) {
        if (Object.keys(values).some((key) => records.has(key))) return false;
        Object.entries(values).forEach(([key, value]) =>
          records.set(key, value)
        );
        return true;
      },
    };
    const host = createKeyringHost(storage);
    const ring = new SoftwareKeyring(host, {
      captureEvmSubmission: () => ({
        assertCurrent() {
          return undefined;
        },
        async persistSigned(record) {
          saved = record;
          entered.resolve();
          await ack.promise;
        },
      }),
    });
    const state: any = {
      activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
      activeNetwork: {
        kind: INetworkType.Ethereum,
        chainId: 7654321,
        slip44: 60,
        label: 'Test',
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
    const address = state.accounts.HDAccount[0].address;
    const provider = {
      verifyConfiguredChainId: jest.fn(async () => undefined),
      getNetwork: jest.fn(async () => ({ chainId: 7654321 })),
      getTransactionCount: jest.fn(async () => 7),
      estimateGas: jest.fn(async () => BigNumber.from(42000)),
      sendTransaction: jest.fn(async (raw: string) => ({
        hash: Transaction.from(raw).hash,
      })),
    };
    jest
      .spyOn(ring.ethereumTransaction, 'web3Provider', 'get')
      .mockReturnValue(provider as any);
    try {
      const result = ring.ethereumTransaction
        .sendFormattedTransaction(
          {
            from: address,
            to: `0x${'22'.repeat(20)}`,
            value: 123,
            chainId: 7654321,
            gasLimit: 42000,
            gasPrice: 2,
            nonce: 7,
          } as any,
          true
        )
        .catch((e) => e);
      await Promise.race([
        entered.promise,
        result.then((value) => {
          throw Error(`Finished before persistence: ${JSON.stringify(value)}`);
        }),
      ]);
      expect(saved.from).toBe(address);
      expect(saved.rawTransaction).not.toContain(phrase);
      expect(saved.rawTransaction).not.toContain(password);
      if (mode === 'lock') await ring.lockWallet();
      if (mode === 'account-change')
        state.activeAccount = { id: 1, type: KeyringAccountType.HDAccount };
      ack.resolve();
      const outcome = await result;
      if (mode === 'healthy') {
        expect(outcome.hash).toBe(saved.hash);
        expect(provider.sendTransaction).toHaveBeenCalledWith(
          saved.rawTransaction
        );
      } else {
        expect(outcome).toMatchObject({ transactionNotBroadcast: true });
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      }
    } finally {
      ack.resolve();
      await ring.destroy();
      jest.restoreAllMocks();
    }
  }
);
