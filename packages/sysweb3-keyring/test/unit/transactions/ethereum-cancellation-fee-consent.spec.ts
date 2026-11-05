// Public deterministic keys; only local signing and in-memory device/RPC fixtures.
jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };

import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import * as ethersCompat from '../../../src/ethers-v6';
import { BigNumber, serializeTransaction } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import * as localSigner from '../../../src/transactions/evm-local-signer';
import { KeyringAccountType } from '../../../src/types';
import { createTestSubmissionCapture } from '../../helpers/evm-submission';

// Keep real signed-response normalization; the shared fixture omits it.
jest.mock('../../../src/providers', () => ({
  ...jest.requireActual('../../../src/providers'),
  CustomJsonRpcProvider: jest.fn(),
}));

const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const PAYER = wallet.address;
const SMART = `0x${'22'.repeat(20)}`;
const OTHER = `0x${'33'.repeat(20)}`;
const CHAIN = 5700;
const MAXIMUM_FEE = '5040000'; // 42000 gas * 120 wei.
const routes = [
  { type: KeyringAccountType.HDAccount, id: 3 },
  { type: KeyringAccountType.Ledger, id: 4 },
  { type: KeyringAccountType.Trezor, id: 5 },
];
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};

function fixture(
  legacy: boolean,
  devices = true,
  { nonce = 8, originalPrice = 100n, originalTip = 10n } = {}
) {
  const original = Transaction.from({
    type: legacy ? 0 : 2,
    chainId: CHAIN,
    nonce,
    to: OTHER,
    value: 7,
    data: '0x',
    gasLimit: 21000,
    ...(legacy
      ? { gasPrice: originalPrice }
      : { maxFeePerGas: originalPrice, maxPriorityFeePerGas: originalTip }),
  });
  original.signature = wallet.signingKey.sign(original.unsignedHash);
  const row = {
    ...original.toJSON(),
    signature: original.signature,
    hash: original.hash,
    from: PAYER,
    nonce: original.nonce,
    gasLimit: BigNumber.from(original.gasLimit),
    gasPrice:
      original.gasPrice == null ? null : BigNumber.from(original.gasPrice),
    maxFeePerGas:
      original.maxFeePerGas == null
        ? null
        : BigNumber.from(original.maxFeePerGas),
    maxPriorityFeePerGas:
      original.maxPriorityFeePerGas == null
        ? null
        : BigNumber.from(original.maxPriorityFeePerGas),
    value: BigNumber.from(original.value),
    blockNumber: null,
    blockHash: null,
  };
  const state: any = {
    activeAccountType: KeyringAccountType.SmartAccount,
    activeAccountId: 7,
    activeNetwork: {
      kind: 'ethereum',
      chainId: CHAIN,
      slip44: 60,
      currency: 'tsys',
      url: 'https://offline.invalid',
    },
    accounts: {
      [KeyringAccountType.SmartAccount]: {
        7: { address: SMART },
        8: { address: OTHER },
      },
      [KeyringAccountType.HDAccount]: {
        3: { address: PAYER },
        9: { address: OTHER },
      },
      [KeyringAccountType.Ledger]: { 4: { address: PAYER } },
      [KeyringAccountType.Trezor]: { 5: { address: PAYER } },
    },
  };
  const sent: Transaction[] = [];
  const provider = {
    getTransaction: jest.fn(async (): Promise<typeof row | null> => row),
    getGasPrice: jest.fn(async () => BigNumber.from(100)),
    getNetwork: jest.fn(async () => ({ chainId: CHAIN })),
    verifyConfiguredChainId: jest.fn(async () => undefined),
    sendTransaction: jest.fn(async (raw: string) => {
      const signed = Transaction.from(raw);
      sent.push(signed);
      return { hash: signed.hash, from: signed.from, nonce: signed.nonce };
    }),
  };
  let currentProvider = provider;
  let generation = 0;
  const getKey = jest.fn(() => ({
    address: PAYER,
    decryptedPrivateKey: wallet.privateKey,
  }));
  const signature = (transaction: any) =>
    wallet.signingKey.sign(
      Transaction.from(
        typeof transaction === 'string'
          ? transaction
          : serializeTransaction(transaction)
      ).unsignedHash
    );
  const ledger = {
    evm: {
      signEVMTransaction: jest.fn(async ({ rawTx }) => {
        const signed = signature(`0x${rawTx}`);
        return {
          r: signed.r.slice(2),
          s: signed.s.slice(2),
          v: signed.v.toString(16),
        };
      }),
    },
  };
  const trezor = {
    signEthTransaction: jest.fn(async ({ tx }) => {
      const signed = signature(tx);
      return {
        success: true,
        payload: { r: signed.r, s: signed.s, v: signed.v },
      };
    }),
  };
  const sdk = new EthereumTransactions(
    () => state.activeNetwork,
    getKey,
    () => state,
    devices ? (ledger as any) : undefined,
    devices ? (trezor as any) : undefined,
    () => {
      const captured = generation;
      return () => {
        if (generation !== captured) throw new Error('Session changed');
      };
    },
    createTestSubmissionCapture()
  );
  const providerAccess = jest.fn(() => currentProvider);
  Object.defineProperty(sdk, 'web3Provider', { get: providerAccess });
  jest
    .spyOn(sdk, 'getFeeDataWithDynamicMaxPriorityFeePerGas')
    .mockResolvedValue({
      maxFeePerGas: BigNumber.from(100),
      maxPriorityFeePerGas: BigNumber.from(10),
    });
  const validateOriginal = jest.fn((value) => {
    expect(value.hash).toBe(original.hash);
    expect(value.from.toLowerCase()).toBe(PAYER.toLowerCase());
    expect(value.nonce).toBe(nonce);
  });
  const options = (targetAccount = routes[0]) => ({
    targetAccount: { ...targetAccount },
    approvedMaximumFee: MAXIMUM_FEE,
    assertCurrentContext: () => undefined,
    validateOriginal,
  });
  const run = (opts: any = options(), fallbackNonce?: number) =>
    sdk.cancelSentTransaction(original.hash!, legacy, fallbackNonce, opts);
  const noSigning = () => {
    expect(getKey).not.toHaveBeenCalled();
    expect(ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
    expect(trezor.signEthTransaction).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  };
  return {
    sdk,
    state,
    provider,
    providerAccess,
    ledger,
    trezor,
    getKey,
    sent,
    options,
    run,
    noSigning,
    cycle: () => {
      generation += 2;
    },
    switchProvider: () => {
      currentProvider = { ...provider };
    },
  };
}

afterEach(() => jest.restoreAllMocks());

describe.each([true, false])(
  'cancellation fee consent (legacy=%s)',
  (legacy) => {
    it.each(routes)(
      'previews without credentials or devices for target $type',
      async (target) => {
        const f = fixture(legacy, false);
        await expect(
          f.run({
            ...f.options(target),
            previewOnly: true,
            approvedMaximumFee: undefined,
          })
        ).resolves.toEqual({
          isCanceled: false,
          error: false,
          maximumFee: MAXIMUM_FEE,
        });
        f.noSigning();
        expect(f.state.activeAccountType).toBe(KeyringAccountType.SmartAccount);
        expect(f.state.activeAccountId).toBe(7);
      }
    );

    it.each(routes)(
      'signs with approved target $type and leaves selection unchanged',
      async (target) => {
        const f = fixture(legacy);
        await expect(f.run(f.options(target))).resolves.toMatchObject({
          isCanceled: true,
        });
        expect(f.sent).toHaveLength(1);
        const tx = f.sent[0];
        expect(tx.from).toBe(PAYER);
        expect(tx.to).toBe(PAYER);
        expect(tx.nonce).toBe(8);
        expect(tx.value).toBe(0n);
        expect(tx.data).toBe('0x');
        expect(tx.gasLimit).toBe(42000n);
        expect(tx.gasLimit * (legacy ? tx.gasPrice! : tx.maxFeePerGas!)).toBe(
          BigInt(MAXIMUM_FEE)
        );
        expect(f.state.activeAccountType).toBe(KeyringAccountType.SmartAccount);
        expect(f.state.activeAccountId).toBe(7);
        if (target.type === KeyringAccountType.HDAccount)
          expect(f.getKey).toHaveBeenCalledWith(target);
        else expect(f.getKey).not.toHaveBeenCalled();
        if (target.type === KeyringAccountType.Ledger)
          expect(
            f.ledger.evm.signEVMTransaction.mock.calls[0][0].accountIndex
          ).toBe(4);
        if (target.type === KeyringAccountType.Trezor)
          expect(f.trezor.signEthTransaction.mock.calls[0][0].index).toBe('5');
      }
    );

    it.each(routes)(
      'preserves nonce zero and the exact large fee for target $type',
      async (target) => {
        const f = fixture(legacy, true, {
          nonce: 0,
          originalPrice: 9_007_199_254_740_993n,
          originalTip: 1n,
        });
        const price = 10_808_639_105_689_191n;
        const ceiling = (42_000n * price).toString();
        const options = f.options(target);
        await expect(
          f.run({ ...options, previewOnly: true })
        ).resolves.toMatchObject({ maximumFee: ceiling });
        f.noSigning();

        await expect(
          f.run({ ...options, approvedMaximumFee: ceiling })
        ).resolves.toMatchObject({ isCanceled: true });
        const expected = Transaction.from({
          type: legacy ? 0 : 2,
          chainId: CHAIN,
          nonce: 0,
          to: PAYER,
          value: 0,
          data: '0x',
          gasLimit: 42_000,
          ...(legacy
            ? { gasPrice: price }
            : { maxFeePerGas: price, maxPriorityFeePerGas: 12n }),
        });
        expected.signature = wallet.signingKey.sign(expected.unsignedHash);
        expect(f.sent.map((tx) => tx.serialized)).toEqual([
          expected.serialized,
        ]);
      }
    );

    it.each(['field replacement', 'in-place fee mutation'])(
      'retains the authenticated nonce and fees during a held quote with %s',
      async (mutation) => {
        const f = fixture(legacy, false, {
          nonce: 0,
          originalPrice: 120n,
          originalTip: 20n,
        });
        const ready = deferred<void>();
        const resume = deferred<void>();
        if (legacy) {
          f.provider.getGasPrice.mockImplementationOnce(async () => {
            ready.resolve();
            await resume.promise;
            return BigNumber.from(100);
          });
        } else {
          jest
            .mocked(f.sdk.getFeeDataWithDynamicMaxPriorityFeePerGas)
            .mockImplementationOnce(async () => {
              ready.resolve();
              await resume.promise;
              return {
                maxFeePerGas: BigNumber.from(100),
                maxPriorityFeePerGas: BigNumber.from(10),
              };
            });
        }

        const options = f.options();
        const pending = f.run({ ...options, approvedMaximumFee: '6048000' });
        await ready.promise;
        const [original] = options.validateOriginal.mock.calls[0];
        original.nonce = 91;
        if (mutation === 'field replacement') {
          original.gasPrice = BigNumber.from(1);
          original.maxFeePerGas = BigNumber.from(1);
          original.maxPriorityFeePerGas = BigNumber.from(1);
        } else {
          Object.assign(original.gasPrice, { value: 1n });
          Object.assign(original.maxFeePerGas, { value: 1n });
          Object.assign(original.maxPriorityFeePerGas, { value: 1n });
        }
        resume.resolve();

        await expect(pending).resolves.toMatchObject({ isCanceled: true });
        expect(f.sent).toHaveLength(1);
        const [sent] = f.sent;
        expect(sent.nonce).toBe(0);
        expect(sent.gasLimit).toBe(42000n);
        expect(legacy ? sent.gasPrice : sent.maxFeePerGas).toBe(144n);
        expect(sent.maxPriorityFeePerGas).toBe(legacy ? null : 24n);
      }
    );

    it('retains authenticated original fees after synchronous field replacement', async () => {
      const f = fixture(legacy, false, {
        nonce: 0,
        originalPrice: 120n,
        originalTip: 20n,
      });
      const options = f.options();
      options.validateOriginal.mockImplementationOnce((original) => {
        expect(original.nonce).toBe(0);
        original.gasPrice = BigNumber.from(1);
        original.maxFeePerGas = BigNumber.from(1);
        original.maxPriorityFeePerGas = BigNumber.from(1);
      });
      await expect(
        f.run({ ...options, approvedMaximumFee: '6048000' })
      ).resolves.toMatchObject({ isCanceled: true });
      expect(f.sent).toHaveLength(1);
      expect(legacy ? f.sent[0].gasPrice : f.sent[0].maxFeePerGas).toBe(144n);
      expect(f.sent[0].maxPriorityFeePerGas).toBe(legacy ? null : 24n);
    });

    it('does not read hostile nonce or fee getters after admitting a software original', async () => {
      const f = fixture(legacy, false, { nonce: 0 });
      const options = f.options();
      const lateRead = jest.fn(() => {
        throw new Error('Unexpected late original read');
      });
      options.validateOriginal.mockImplementationOnce((original) => {
        expect(original.nonce).toBe(0);
        for (const field of [
          'nonce',
          'gasPrice',
          'maxFeePerGas',
          'maxPriorityFeePerGas',
        ])
          Object.defineProperty(original, field, { get: lateRead });
      });
      await expect(f.run(options)).resolves.toMatchObject({ isCanceled: true });
      expect(lateRead).not.toHaveBeenCalled();
      expect(f.sent).toHaveLength(1);
      expect(f.sent[0]).toMatchObject({ nonce: 0, to: PAYER, from: PAYER });
    });

    it('refuses a changed final software cancellation recipient before signing', async () => {
      const f = fixture(legacy, false);
      const resolve = ethersCompat.resolveProperties;
      jest
        .spyOn(ethersCompat, 'resolveProperties')
        .mockImplementationOnce(async (value) => ({
          ...(await resolve(value)),
          to: OTHER,
        }));
      const sign = jest.spyOn(localSigner, 'signTransaction');
      await expect(f.run()).resolves.toMatchObject({
        isCanceled: false,
        error: true,
        transactionNotBroadcast: true,
      });
      expect(sign).not.toHaveBeenCalled();
      expect(f.provider.sendTransaction).not.toHaveBeenCalled();
    });

    it('signs the host-admitted fallback nonce zero without inferring another nonce', async () => {
      const f = fixture(legacy, false);
      f.provider.getTransaction.mockResolvedValueOnce(null);
      const validateOriginal = jest.fn((original) =>
        expect(original).toBeNull()
      );
      await expect(
        f.run({ ...f.options(), validateOriginal }, 0)
      ).resolves.toMatchObject({ isCanceled: true });
      expect(validateOriginal).toHaveBeenCalledWith(null);
      expect(f.sent).toHaveLength(1);
      expect(f.sent[0]).toMatchObject({
        nonce: 0,
        from: PAYER,
        to: PAYER,
        value: 0n,
        data: '0x',
      });
    });

    it.each([undefined, '', '00', '-1', '1.5', '0x100', 1, '9'.repeat(79)])(
      'rejects invalid fee approval %p before RPC or signing',
      async (cap) => {
        const f = fixture(legacy);
        await expect(
          f.run({ ...f.options(), approvedMaximumFee: cap })
        ).rejects.toThrow('Cancellation fee approval required');
        expect(f.providerAccess).not.toHaveBeenCalled();
        expect(f.provider.getTransaction).not.toHaveBeenCalled();
        f.noSigning();
      }
    );

    it.each(routes)(
      'rejects an insufficient fee ceiling before target $type credentials',
      async (target) => {
        const f = fixture(legacy);
        await expect(
          f.run({ ...f.options(target), approvedMaximumFee: '5039999' })
        ).rejects.toThrow('Cancellation fee exceeds approval');
        f.noSigning();
      }
    );

    it.each(routes.slice(1))(
      'rejects missing target $type hardware before provider access',
      async (target) => {
        const f = fixture(legacy, false);
        await expect(f.run(f.options(target))).rejects.toMatchObject({
          code: 'HARDWARE_SIGNER_UNAVAILABLE',
        });
        expect(f.providerAccess).not.toHaveBeenCalled();
        f.noSigning();
      }
    );

    it.each(routes)(
      'validates the final populated gas envelope for target $type',
      async (target) => {
        const f = fixture(legacy);
        const resolve = ethersCompat.resolveProperties;
        jest
          .spyOn(ethersCompat, 'resolveProperties')
          .mockImplementationOnce(async (value) => ({
            ...(await resolve(value)),
            gasLimit: BigNumber.from(42001),
          }));
        const sign = jest.spyOn(localSigner, 'signTransaction');
        await expect(f.run(f.options(target))).resolves.toEqual({
          isCanceled: false,
          error: true,
          transactionNotBroadcast: true,
        });
        expect(f.ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
        expect(f.trezor.signEthTransaction).not.toHaveBeenCalled();
        expect(sign).not.toHaveBeenCalled();
        expect(f.provider.sendTransaction).not.toHaveBeenCalled();
      }
    );
  }
);

it.each([
  'selected account',
  'selected address',
  'target address',
  'network',
  'provider',
  'session',
])(
  'rejects changed %s while reading fees without changing selection',
  async (change) => {
    const f = fixture(true);
    const ready = deferred<void>();
    const gate = deferred<BigNumber>();
    f.provider.getGasPrice.mockImplementationOnce(() => {
      ready.resolve();
      return gate.promise;
    });
    const pending = f.run();
    const rejected = expect(pending).rejects.toThrow(
      /context changed|Session changed/
    );
    await ready.promise;
    if (change === 'selected account') f.state.activeAccountId = 8;
    if (change === 'selected address')
      f.state.accounts[KeyringAccountType.SmartAccount][7].address = OTHER;
    if (change === 'target address')
      f.state.accounts[KeyringAccountType.HDAccount][3].address = OTHER;
    if (change === 'network') f.state.activeNetwork.chainId++;
    if (change === 'provider') f.switchProvider();
    if (change === 'session') f.cycle();
    gate.resolve(BigNumber.from(100));
    await rejected;
    f.noSigning();
  }
);

it('captures preview, fee approval, and target identity before asynchronous work', async () => {
  const f = fixture(true, false);
  const ready = deferred<void>();
  const gate = deferred<BigNumber>();
  f.provider.getGasPrice.mockImplementationOnce(() => {
    ready.resolve();
    return gate.promise;
  });
  const opts: any = {
    ...f.options(routes[1]),
    previewOnly: true,
    approvedMaximumFee: undefined,
  };
  const pending = f.run(opts);
  await ready.promise;
  opts.previewOnly = false;
  opts.approvedMaximumFee = '0';
  opts.targetAccount.id = 99;
  gate.resolve(BigNumber.from(100));
  await expect(pending).resolves.toEqual({
    isCanceled: false,
    error: false,
    maximumFee: MAXIMUM_FEE,
  });
  f.noSigning();
});

it('captures the approved fee cap while the network fee changes', async () => {
  const f = fixture(true);
  const ready = deferred<void>();
  const gate = deferred<BigNumber>();
  f.provider.getGasPrice.mockImplementationOnce(() => {
    ready.resolve();
    return gate.promise;
  });
  const opts = f.options();
  const pending = f.run(opts);
  await ready.promise;
  opts.approvedMaximumFee = '999999999';
  gate.resolve(BigNumber.from(101));
  await expect(pending).rejects.toThrow('Cancellation fee exceeds approval');
  f.noSigning();
});
