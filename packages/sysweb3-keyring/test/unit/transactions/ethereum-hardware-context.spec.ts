jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };
jest.mock('../../../src/providers', () => ({
  ...jest.requireActual('../../../src/providers'),
  CustomJsonRpcProvider: jest.fn(),
}));

import { Interface } from 'ethers/abi';
import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { BigNumber, serializeTransaction } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { KeyringAccountType } from '../../../src/types';
import {
  admitTestSignedDispatch,
  createTestSubmissionCapture,
} from '../../helpers/evm-submission';
const tokenApproval = {
  assertCurrent: () => undefined,
  signal: new AbortController().signal,
};

const specializedApproval = {
  mode: 'specialized' as const,
  assertCurrent: () => undefined,
};

// The public key is an offline device response fixture, never a live wallet.
// SDK serialization/context/broadcast classification are real; physical I/O and
// RPC are deterministic in-memory boundaries. Pali additionally tests the real
// Ledger APDU encoder and Trezor adapter against these same signing scenarios.
const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const recipient = `0x${'22'.repeat(20)}`;
const deferred = <T>() => {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => (resolve = done));
  return { promise, resolve };
};

describe.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
  'ordinary %s EVM approval context',
  (kind) => {
    let sdk: EthereumTransactions;
    let state: any;
    let provider: any;
    let otherProvider: any;
    let device: jest.Mock;
    let getKey: jest.Mock;
    let sessionGeneration: number;
    let softwareUsed: boolean;
    const request = (legacy = false) => ({
      from: wallet.address,
      to: recipient,
      value: '12345',
      data: '0x',
      gasLimit: '21000',
      ...(legacy
        ? { gasPrice: '100' }
        : { maxFeePerGas: '100', maxPriorityFeePerGas: '2' }),
    });
    const send = (legacy = false) =>
      sdk.sendFormattedTransaction(
        request(legacy),
        legacy,
        specializedApproval
      );

    beforeEach(() => {
      state = {
        activeAccountType: kind,
        activeAccountId: 0,
        activeNetwork: {
          kind: 'ethereum',
          chainId: 57057,
          slip44: 60,
          currency: 'tsys',
          url: 'https://rpc-a.invalid',
        },
        accounts: {
          [kind]: {
            0: { id: 0, address: wallet.address },
            1: { id: 1, address: new Wallet(`0x${'33'.repeat(32)}`).address },
          },
        },
      };
      const makeProvider = () => ({
        verifyConfiguredChainId: jest.fn().mockResolvedValue(undefined),
        getTransactionCount: jest.fn().mockResolvedValue(7),
        sendTransaction: jest.fn(async (raw: string) => ({
          hash: Transaction.from(raw).hash,
        })),
      });
      provider = makeProvider();
      otherProvider = makeProvider();
      device = jest.fn(async (raw: string) =>
        wallet.signingKey.sign(Transaction.from(raw).unsignedHash)
      );
      const ledger: any = {
        evm: {
          signEVMTransaction: jest.fn(async ({ rawTx }) => {
            const signature = await device(`0x${rawTx}`);
            return {
              r: signature.r.slice(2),
              s: signature.s.slice(2),
              v: signature.v.toString(16),
            };
          }),
        },
      };
      const trezor: any = {
        signEthTransaction: jest.fn(async ({ tx }) => {
          const signature = await device(
            serializeTransaction({
              ...tx,
              type: tx.gasPrice === undefined ? 2 : 0,
            })
          );
          return {
            success: true,
            payload: {
              r: signature.r,
              s: signature.s,
              v: signature.v.toString(16),
            },
          };
        }),
      };
      getKey = jest.fn(() => {
        throw new Error('Hardware account must not access a software key');
      });
      sessionGeneration = 1;
      softwareUsed = false;
      sdk = new EthereumTransactions(
        () => state.activeNetwork,
        getKey,
        () => state,
        ledger,
        trezor,
        () => {
          const captured = sessionGeneration;
          return () => {
            if (sessionGeneration !== captured)
              throw new Error('Wallet signing context changed');
          };
        },
        createTestSubmissionCapture()
      );
      jest.spyOn(sdk, 'setWeb3Provider').mockImplementation((network: any) => {
        (sdk as any)._web3Provider =
          network.url === 'https://rpc-a.invalid' ? provider : otherProvider;
        (sdk as any)._web3ProviderKey = `${network.chainId}|${network.url}`;
      });
    });
    afterEach(() => {
      if (!softwareUsed) expect(getKey).not.toHaveBeenCalled();
      jest.restoreAllMocks();
    });

    for (const legacy of [false, true]) {
      it.each([
        { name: 'zero', value: 0, expected: 0 },
        { name: 'number', value: 7, expected: 7 },
        { name: 'hex', value: '0x07', expected: 7 },
        { name: 'hex zero', value: '0x00', expected: 0 },
        { name: 'hex object', value: { _hex: '0x07' }, expected: 7 },
        {
          name: 'maximum safe integer',
          value: Number.MAX_SAFE_INTEGER,
          expected: Number.MAX_SAFE_INTEGER,
        },
        { name: 'bigint', value: 7n, expected: 7 },
        { name: 'BigNumber', value: BigNumber.from(7), expected: 7 },
      ])(
        `preserves the explicit $name nonce instead of the RPC value (legacy ${legacy})`,
        async ({ value, expected }) => {
          provider.getTransactionCount.mockResolvedValue(99);
          await sdk.sendFormattedTransaction(
            { ...request(legacy), nonce: value } as any,
            legacy,
            specializedApproval
          );
          expect(device).toHaveBeenCalledTimes(1);
          expect(Transaction.from(device.mock.calls[0][0]).nonce).toBe(
            expected
          );
          expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
          expect(
            Transaction.from(provider.sendTransaction.mock.calls[0][0]).nonce
          ).toBe(expected);
          expect(provider.getTransactionCount).not.toHaveBeenCalled();
        }
      );

      it.each([undefined, null])(
        `fills a missing nonce from pending RPC only when nullish (legacy ${legacy}, nonce %s)`,
        async (nonce) => {
          provider.getTransactionCount.mockResolvedValue(99);
          await sdk.sendFormattedTransaction(
            { ...request(legacy), nonce } as any,
            legacy,
            specializedApproval
          );
          expect(provider.getTransactionCount).toHaveBeenCalledWith(
            wallet.address,
            'pending'
          );
          expect(provider.getTransactionCount).toHaveBeenCalledTimes(1);
          expect(
            Transaction.from(provider.sendTransaction.mock.calls[0][0]).nonce
          ).toBe(99);
        }
      );

      it(`captures an explicit nonce before awaited gas preparation (legacy ${legacy})`, async () => {
        const entered = deferred<void>(),
          gas = deferred<any>();
        provider.estimateGas = jest.fn(() => {
          entered.resolve();
          return gas.promise;
        });
        const params = {
          ...request(legacy),
          nonce: 7,
          gasLimit: undefined,
        } as any;
        const sending = sdk.sendFormattedTransaction(
          params,
          legacy,
          specializedApproval
        );
        await entered.promise;
        params.nonce = 99;
        gas.resolve(BigNumber.from(21000));
        await sending;
        expect(Transaction.from(device.mock.calls[0][0]).nonce).toBe(7);
        expect(
          Transaction.from(provider.sendTransaction.mock.calls[0][0]).nonce
        ).toBe(7);
        expect(provider.getTransactionCount).not.toHaveBeenCalled();
      });
    }

    it.each([false, true])(
      'detaches all supplied bytes and quantities before a held fee await (legacy %s)',
      async (legacy) => {
        const entered = deferred<void>(),
          gas = deferred<any>();
        provider.estimateGas = jest.fn(() => {
          entered.resolve();
          return gas.promise;
        });
        const value = { _hex: '0x3039' },
          nonce = { _hex: '0x00' };
        const bytes = new Uint8Array([0x12, 0x34]);
        const accessList = [
          { address: recipient, storageKeys: [`0x${'44'.repeat(32)}`] },
        ];
        const params: any = {
          ...request(legacy),
          value,
          nonce,
          data: bytes,
          gasLimit: undefined,
          ...(legacy ? {} : { accessList }),
        };
        const pending = sdk.sendFormattedTransaction(
          params,
          legacy,
          specializedApproval
        );
        await entered.promise;
        params.to = wallet.address;
        value._hex = '0xffff';
        nonce._hex = '0x63';
        bytes[0] = 0xff;
        accessList[0].storageKeys[0] = `0x${'55'.repeat(32)}`;
        gas.resolve(BigNumber.from(100000));
        await pending;
        const signed = Transaction.from(
          provider.sendTransaction.mock.calls[0][0]
        );
        expect(signed.to).toBe(recipient);
        expect(signed.value).toBe(12345n);
        expect(signed.nonce).toBe(0);
        expect(signed.data).toBe('0x1234');
        if (!legacy)
          expect(signed.accessList).toEqual([
            { address: recipient, storageKeys: [`0x${'44'.repeat(32)}`] },
          ]);
        expect(signed.unsignedSerialized).toBe(
          Transaction.from(device.mock.calls[0][0]).unsignedSerialized
        );
      }
    );

    if (kind === KeyringAccountType.Trezor)
      it('rejects a device-mutated Trezor envelope before retaining or dispatching it', async () => {
        const persistSigned = jest.fn(async () => undefined);
        (sdk as any).captureSubmissionLifecycle = () => ({
          assertCurrent: () => undefined,
          persistSigned,
        });
        (sdk as any).trezorSigner.signEthTransaction.mockImplementationOnce(
          async ({ tx }) => {
            tx.nonce = '0x63';
            const signature = wallet.signingKey.sign(
              Transaction.from(serializeTransaction({ ...tx, type: 2 }))
                .unsignedHash
            );
            return { success: true, payload: signature };
          }
        );
        await expect(
          sdk.sendFormattedTransaction(
            { ...request(), nonce: 0 } as any,
            false,
            specializedApproval
          )
        ).rejects.toMatchObject({ transactionNotBroadcast: true });
        expect(persistSigned).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      });

    it.each([null, undefined])(
      'rejects a missing request %s before transaction work',
      async (params) => {
        await expect(
          sdk.sendFormattedTransaction(params as any, true, specializedApproval)
        ).rejects.toMatchObject({ transactionNotBroadcast: true });
        expect(device).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      }
    );

    it('preserves a supplied zero legacy gas price rather than autofilling it', async () => {
      provider.getGasPrice = jest.fn().mockResolvedValue(BigNumber.from(99));
      await sdk.sendFormattedTransaction(
        { ...request(true), nonce: 0, gasPrice: '0x0' } as any,
        true,
        specializedApproval
      );
      expect(
        Transaction.from(provider.sendTransaction.mock.calls[0][0]).gasPrice
      ).toBe(0n);
      expect(provider.getGasPrice).not.toHaveBeenCalled();
    });

    it.each([
      'chainId',
      'nonce',
      'gasLimit',
      'gasPrice',
      'maxFeePerGas',
      'maxPriorityFeePerGas',
      'value',
      'type',
    ])(
      'validates original %s scalar spellings before normalization',
      async (field) => {
        for (const malformed of ['', ' 0 ', '+0', '0'.repeat(81)]) {
          const params: any = {
            ...request(true),
            nonce: 0,
            [field]: malformed,
          };
          await expect(
            sdk.sendFormattedTransaction(params, true, specializedApproval)
          ).rejects.toMatchObject({ transactionNotBroadcast: true });
        }
        expect(provider.getTransactionCount).not.toHaveBeenCalled();
        expect(device).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      }
    );

    it.each([-1, 1.5, Number.MAX_SAFE_INTEGER + 1, '-1', '9007199254740992'])(
      'rejects an invalid explicit nonce %s before RPC, device or broadcast',
      async (nonce) => {
        await expect(
          sdk.sendFormattedTransaction(
            { ...request(), nonce } as any,
            false,
            specializedApproval
          )
        ).rejects.toMatchObject({ transactionNotBroadcast: true });
        expect(provider.getTransactionCount).not.toHaveBeenCalled();
        expect(device).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      }
    );

    it.each([false, true])(
      'preserves exact valid fields and one broadcast (legacy %s)',
      async (legacy) => {
        const response = await send(legacy);
        expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
        expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
        const tx = Transaction.from(provider.sendTransaction.mock.calls[0][0]);
        expect(tx).toMatchObject({
          from: wallet.address,
          to: recipient,
          chainId: BigInt(57057),
          nonce: 7,
          value: BigInt(12345),
          gasLimit: BigInt(21000),
          data: '0x',
          type: legacy ? 0 : 2,
        });
        expect(response.hash).toBe(tx.hash);
        expect(device).toHaveBeenCalledTimes(1);
      }
    );

    it.each([
      'account',
      'network',
      'in-place network',
      'in-place address',
      'session',
    ])('discards a valid signature after pending %s switch', async (change) => {
      const entered = deferred<void>();
      const resume = deferred<void>();
      const implementation = device.getMockImplementation()!;
      device.mockImplementationOnce(async (raw: string) => {
        entered.resolve();
        await resume.promise;
        return implementation(raw);
      });
      const signing = send();
      const rejection = expect(signing).rejects.toMatchObject({
        transactionNotBroadcast: true,
      });
      await entered.promise;
      if (change === 'account') state.activeAccountId = 1;
      if (change === 'network')
        state.activeNetwork = {
          ...state.activeNetwork,
          url: 'https://rpc-b.invalid',
        };
      if (change === 'in-place network') state.activeNetwork.chainId = 1;
      if (change === 'in-place address')
        state.accounts[kind][0].address = recipient;
      if (change === 'session') sessionGeneration += 1;
      resume.resolve();
      await rejection;
      expect(provider.sendTransaction).not.toHaveBeenCalled();
      expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
    });

    it('does not ask the device to sign after the account changes during nonce lookup', async () => {
      const entered = deferred<void>();
      const nonce = deferred<number>();
      provider.getTransactionCount.mockImplementationOnce(() => {
        entered.resolve();
        return nonce.promise;
      });
      const signing = send();
      const rejection = expect(signing).rejects.toMatchObject({
        transactionNotBroadcast: true,
      });
      await entered.promise;
      state.activeAccountId = 1;
      nonce.resolve(7);
      await rejection;
      expect(device).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
      expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
    });

    it.each(['estimateGas', 'getFeeData'])(
      'stops before the device after context changes during %s',
      async (method) => {
        const entered = deferred<void>();
        const read = deferred<any>();
        provider[method] = jest.fn(() => {
          entered.resolve();
          return read.promise;
        });
        const params: any = request();
        if (method === 'estimateGas') delete params.gasLimit;
        else {
          delete params.maxFeePerGas;
          delete params.maxPriorityFeePerGas;
        }
        const signing = sdk.sendFormattedTransaction(
          params,
          false,
          specializedApproval
        );
        const rejection = expect(signing).rejects.toMatchObject({
          transactionNotBroadcast: true,
        });
        await entered.promise;
        state.activeNetwork = {
          ...state.activeNetwork,
          url: 'https://rpc-b.invalid',
        };
        read.resolve(
          method === 'estimateGas'
            ? '21000'
            : { maxFeePerGas: '100', maxPriorityFeePerGas: '2' }
        );
        await rejection;
        expect(device).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
        expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
      }
    );

    it('retains the acknowledged hash when selection changes only after publication starts', async () => {
      const entered = deferred<void>();
      const ack = deferred<any>();
      let hash: string;
      provider.sendTransaction.mockImplementationOnce((raw: string) => {
        hash = Transaction.from(raw).hash!;
        entered.resolve();
        return ack.promise;
      });
      const signing = send();
      await entered.promise;
      state.activeAccountId = 1;
      state.activeNetwork = {
        ...state.activeNetwork,
        url: 'https://rpc-b.invalid',
      };
      ack.resolve({ hash: hash! });
      await expect(signing).resolves.toEqual({ hash: hash! });
      expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
      expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
      expect(device).toHaveBeenCalledTimes(1);
    });

    describe('ERC20 base units', () => {
      const tokenAddress = `0x${'44'.repeat(20)}`;
      const maxUnits = ((1n << 256n) - 1n).toString();
      const transfer = new Interface(['function transfer(address,uint256)']);
      let captureSubmission: jest.SpyInstance;
      const tokenRequest = () => ({
        networkUrl: state.activeNetwork.url,
        tokenAddress,
        receiver: recipient,
        gasLimit: '200000',
      });
      const sendExact = (fields: {
        tokenAmountUnits?: unknown;
        tokenAmount?: string;
        decimals?: number;
        isLegacy?: boolean;
      }) =>
        sdk.sendSignedErc20Transaction(
          {
            ...tokenRequest(),
            isLegacy: false,
            ...fields,
            ...(fields.isLegacy
              ? { gasPrice: 100 }
              : { maxFeePerGas: 100, maxPriorityFeePerGas: 2 }),
          } as Parameters<typeof sdk.sendSignedErc20Transaction>[0],
          tokenApproval
        );
      const expectNoTokenIo = () => {
        expect(captureSubmission).not.toHaveBeenCalled();
        expect(provider.getFeeData).not.toHaveBeenCalled();
        expect(provider.getGasPrice).not.toHaveBeenCalled();
        expect(provider.getTransactionCount).not.toHaveBeenCalled();
        expect(device).not.toHaveBeenCalled();
        expect(provider.sendTransaction).not.toHaveBeenCalled();
      };
      const expectSignedAmount = (units: string, isLegacy: boolean) => {
        expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
        const tx = Transaction.from(provider.sendTransaction.mock.calls[0][0]);
        expect(tx).toMatchObject({
          from: wallet.address,
          to: tokenAddress,
          value: 0n,
          type: isLegacy ? 0 : 2,
          nonce: 7,
        });
        expect(
          Array.from(transfer.decodeFunctionData('transfer', tx.data))
        ).toEqual([recipient, BigInt(units)]);
        return tx;
      };

      beforeEach(() => {
        captureSubmission = jest.spyOn(sdk as any, 'captureSubmission');
        provider.getGasPrice = jest.fn().mockResolvedValue(BigNumber.from(100));
        provider.getFeeData = jest.fn().mockResolvedValue({
          maxFeePerGas: BigNumber.from(100),
          maxPriorityFeePerGas: BigNumber.from(2),
        });
      });

      it.each([
        [maxUnits, false],
        ['0', true],
      ] as const)(
        'preserves exact device calldata for %s (legacy %s)',
        async (units, isLegacy) => {
          const response = await sendExact({
            tokenAmountUnits: units,
            isLegacy,
          });
          expect(response.hash).toBe(expectSignedAmount(units, isLegacy).hash);
          expect(device).toHaveBeenCalledTimes(1);
        }
      );

      it.each([
        ['sendSignedErc721Transaction', false],
        ['sendSignedErc1155Transaction', true],
      ] as const)(
        'rejects ERC20 amount on %s before RPC or device',
        async (method, isLegacy) => {
          const request = {
            ...tokenRequest(),
            tokenId: '2',
            tokenAmountUnits: maxUnits,
            isLegacy,
          };
          await expect(
            sdk[method](request as any, tokenApproval)
          ).rejects.toThrow('ERC20 amount is not allowed for NFT transfers');
          expectNoTokenIo();
        }
      );

      if (kind === KeyringAccountType.Ledger) {
        it.each([KeyringAccountType.HDAccount, KeyringAccountType.Imported])(
          'preserves exact local calldata for %s',
          async (accountType) => {
            softwareUsed = true;
            state.activeAccountType = accountType;
            state.accounts[accountType] = { ...state.accounts[kind] };
            provider.verifyConfiguredChainId = jest
              .fn()
              .mockResolvedValue(undefined);
            getKey.mockReturnValue({
              address: wallet.address,
              decryptedPrivateKey: wallet.privateKey,
            });
            const response = await sendExact({ tokenAmountUnits: maxUnits });
            expect(response.hash).toBe(
              expectSignedAmount(maxUnits, false).hash
            );
            expect(getKey).toHaveBeenCalledTimes(1);
            expect(device).not.toHaveBeenCalled();
          }
        );

        it.each([
          null,
          1,
          1n,
          '',
          '01',
          '0x1',
          '1e1',
          '1\n',
          '-1',
          (1n << 256n).toString(),
        ])(
          'rejects malformed base units %s before RPC or device',
          async (units) => {
            await expect(
              sendExact({ tokenAmountUnits: units })
            ).rejects.toThrow('Invalid ERC20 amount');
            expectNoTokenIo();
          }
        );

        it.each([
          ['missing', {}],
          ['old amount only', { tokenAmount: '2', isLegacy: true }],
          ['old amount with decimals', { tokenAmount: '2', decimals: 8 }],
          [
            'mixed old and exact amounts',
            { tokenAmount: '2', tokenAmountUnits: '1' },
          ],
          [
            'exact amount with old decimals',
            { tokenAmountUnits: '1', decimals: 255 },
          ],
          [
            'exact amount with explicit undefined old amount',
            { tokenAmountUnits: '1', tokenAmount: undefined },
          ],
          [
            'exact amount with explicit undefined decimals',
            { tokenAmountUnits: '1', decimals: undefined },
          ],
        ] as const)(
          'rejects %s before lifecycle, RPC or device',
          async (_name, fields) => {
            await expect(sendExact(fields)).rejects.toThrow(
              'Invalid ERC20 amount'
            );
            expectNoTokenIo();
          }
        );

        it('rejects stale decimal requests before accessing a software key', async () => {
          softwareUsed = true;
          state.activeAccountType = KeyringAccountType.HDAccount;
          state.accounts.HDAccount = { ...state.accounts[kind] };
          await expect(sendExact({ tokenAmount: '2' })).rejects.toThrow(
            'Invalid ERC20 amount'
          );
          expect(getKey).not.toHaveBeenCalled();
          expectNoTokenIo();
        });
      }
    });

    describe.each([
      [
        'ERC20 one-digit base units',
        'sendSignedErc20Transaction',
        'transfer(address,uint256)',
        ['2'],
      ],
      [
        'ERC20 nine-digit base units',
        'sendSignedErc20Transaction',
        'transfer(address,uint256)',
        ['200000001'],
      ],
      [
        'ERC721 large id',
        'sendSignedErc721Transaction',
        'transferFrom(address,address,uint256)',
        ['9007199254740993'],
      ],
      [
        'ERC1155 large integer',
        'sendSignedErc1155Transaction',
        'safeTransferFrom(address,address,uint256,uint256,bytes)',
        ['9007199254740993'],
      ],
    ] as const)(
      '%s token approval and signing context',
      (_name, method, fragment, [atomic]) => {
        const tokenAddress = `0x${'44'.repeat(20)}`;
        const sendToken = (legacy = false) => {
          // Model the old hardware getter's real empty-key return, not a fake
          // software key. New code must not ask for it on hardware routes at all.
          getKey.mockReturnValue({
            address: wallet.address,
            decryptedPrivateKey: softwareUsed ? wallet.privateKey : '',
          });
          const request = {
            networkUrl: state.activeNetwork.url,
            tokenAddress,
            receiver: recipient,
            gasLimit: '200000',
            ...(legacy
              ? { isLegacy: true as const, gasPrice: '100' }
              : {
                  isLegacy: false as const,
                  maxFeePerGas: '100',
                  maxPriorityFeePerGas: '2',
                }),
          };
          if (method === 'sendSignedErc20Transaction')
            return sdk[method](
              { ...request, tokenAmountUnits: atomic },
              tokenApproval
            );
          if (method === 'sendSignedErc721Transaction')
            return sdk[method](
              { ...request, tokenId: '9007199254740993' },
              tokenApproval
            );
          return sdk[method](
            {
              ...request,
              tokenId: '9007199254740993',
              tokenAmount: atomic,
            },
            tokenApproval
          );
        };

        it.each([false, true])(
          'preserves exact standard calldata and fee fields (legacy %s)',
          async (legacy) => {
            const response = await sendToken(legacy);
            expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
            const tx = Transaction.from(
              provider.sendTransaction.mock.calls[0][0]
            );
            expect(tx).toMatchObject({
              from: wallet.address,
              to: tokenAddress,
              value: BigInt(0),
              nonce: 7,
              chainId: BigInt(57057),
              gasLimit: BigInt(200000),
              type: legacy ? 0 : 2,
            });
            const parsed = new Interface([
              `function ${fragment}`,
            ]).parseTransaction({ data: tx.data })!;
            if (method === 'sendSignedErc20Transaction')
              expect(Array.from(parsed.args)).toEqual([
                recipient,
                BigInt(atomic),
              ]);
            else if (method === 'sendSignedErc721Transaction')
              expect(Array.from(parsed.args)).toEqual([
                wallet.address,
                recipient,
                BigInt(atomic),
              ]);
            else
              expect(Array.from(parsed.args)).toEqual([
                wallet.address,
                recipient,
                BigInt('9007199254740993'),
                BigInt(atomic),
                '0x',
              ]);
            expect(response.hash).toBe(tx.hash);
            expect(device).toHaveBeenCalledTimes(1);
            expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
          }
        );

        it.each(['rejection', 'disconnect'])(
          'does not send after device %s',
          async (failure) => {
            const error = Object.assign(
              new Error(
                failure === 'rejection'
                  ? 'User rejected'
                  : 'Device disconnected'
              ),
              {
                name: failure === 'rejection' ? 'UserCancel' : 'TransportError',
              }
            );
            device.mockRejectedValueOnce(error);
            await expect(sendToken()).rejects.toBe(error);
            expect(device).toHaveBeenCalledTimes(1);
            expect(provider.sendTransaction).not.toHaveBeenCalled();
            expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
          }
        );

        it.each(['account', 'network', 'session'])(
          'discards the valid signature after pending %s switch',
          async (change) => {
            const entered = deferred<void>();
            const resume = deferred<void>();
            const implementation = device.getMockImplementation()!;
            device.mockImplementationOnce(async (raw: string) => {
              entered.resolve();
              await resume.promise;
              return implementation(raw);
            });
            const signing = sendToken();
            const rejection = expect(signing).rejects.toThrow(
              'Wallet signing context changed'
            );
            await entered.promise;
            if (change === 'account') state.activeAccountId = 1;
            if (change === 'network')
              state.activeNetwork = {
                ...state.activeNetwork,
                url: 'https://rpc-b.invalid',
              };
            if (change === 'session') sessionGeneration += 1;
            resume.resolve();
            await rejection;
            expect(provider.sendTransaction).not.toHaveBeenCalled();
            expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
          }
        );

        it('stops before hardware when selection changes during pending nonce read', async () => {
          const entered = deferred<void>();
          const nonce = deferred<number>();
          provider.getTransactionCount.mockImplementationOnce(() => {
            entered.resolve();
            return nonce.promise;
          });
          const signing = sendToken();
          const rejection = expect(signing).rejects.toThrow(
            'Wallet signing context changed'
          );
          await entered.promise;
          state.activeAccountId = 1;
          nonce.resolve(7);
          await rejection;
          expect(device).not.toHaveBeenCalled();
          expect(provider.sendTransaction).not.toHaveBeenCalled();
        });

        if (kind === KeyringAccountType.Ledger)
          describe('software route controls (no physical hardware)', () => {
            beforeEach(() => {
              softwareUsed = true;
              state.activeAccountType = KeyringAccountType.HDAccount;
              state.accounts.HDAccount = { ...state.accounts[kind] };
              provider.verifyConfiguredChainId = jest
                .fn()
                .mockResolvedValue(undefined);
            });

            it('retains the real local-signing success path without requesting a device', async () => {
              const response = await sendToken();
              expect(getKey).toHaveBeenCalledTimes(1);
              expect(device).not.toHaveBeenCalled();
              expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
              const tx = Transaction.from(
                provider.sendTransaction.mock.calls[0][0]
              );
              expect(tx.from).toBe(wallet.address);
              expect(response.hash).toBe(tx.hash);
            });

            it.each(['getTransactionCount', 'verifyConfiguredChainId'])(
              'refuses a stale software result after %s is pending',
              async (method) => {
                const entered = deferred<void>();
                const reply = deferred<any>();
                provider[method].mockImplementationOnce(() => {
                  entered.resolve();
                  return reply.promise;
                });
                const signing = sendToken();
                const rejection = expect(signing).rejects.toThrow(
                  'Wallet signing context changed'
                );
                await entered.promise;
                state.activeAccountId = 1;
                reply.resolve(method === 'getTransactionCount' ? 7 : undefined);
                await rejection;
                expect(getKey).toHaveBeenCalledTimes(1);
                expect(device).not.toHaveBeenCalled();
                expect(provider.sendTransaction).not.toHaveBeenCalled();
                expect(otherProvider.sendTransaction).not.toHaveBeenCalled();
              }
            );
          });
      }
    );
  }
);

describe('EVM cancellation signing context', () => {
  // Public deterministic fixtures, never real wallet keys. Software signing and
  // device transaction encoders are real; provider and device I/O stay in memory.
  const wallet = new Wallet(`0x${'01'.repeat(32)}`);
  const otherWallet = new Wallet(`0x${'02'.repeat(32)}`);
  const PAYER = wallet.address;
  let HASH: string;
  const CHAIN = 5700;
  const accountTypes = [
    KeyringAccountType.HDAccount,
    KeyringAccountType.Imported,
    KeyringAccountType.Ledger,
    KeyringAccountType.Trezor,
  ];
  const deferred = <T>() => {
    let resolve!: (value: T) => void;
    const promise = new Promise<T>((done) => (resolve = done));
    return { promise, resolve };
  };
  const deviceSignature = (params: any) => {
    const tx = Transaction.from(
      typeof params === 'string' ? params : serializeTransaction(params)
    );
    return wallet.signingKey.sign(tx.unsignedHash);
  };

  let state: any;
  let session: object;
  let sdk: EthereumTransactions;
  let provider: any;
  let currentProvider: any;
  let getKey: jest.Mock;
  let ledger: any;
  let trezor: any;
  let signed: Transaction[];
  let hostCurrent: boolean;
  let assertHostContext: () => void;

  const run = (legacy = true, fallbackNonce?: number) =>
    sdk.cancelSentTransaction(HASH, legacy, fallbackNonce, {
      assertCurrentContext: assertHostContext,
      approvedMaximumFee: '9'.repeat(78),
      validateOriginal: () => undefined,
    });
  const original = (nonce = 7, fields: any = {}) => {
    const type = fields.type ?? 2;
    const tx = Transaction.from({
      type,
      chainId: CHAIN,
      nonce,
      to: PAYER,
      value: 0,
      data: '0x',
      gasLimit: 21000,
      ...(type === 0
        ? { gasPrice: (fields.gasPrice ?? 100).toString() }
        : {
            maxFeePerGas: (fields.maxFeePerGas ?? 100).toString(),
            maxPriorityFeePerGas: (
              fields.maxPriorityFeePerGas ?? 10
            ).toString(),
          }),
    });
    tx.signature = wallet.signingKey.sign(tx.unsignedHash);
    HASH = tx.hash!;
    return {
      ...tx.toJSON(),
      signature: tx.signature,
      hash: HASH,
      from: PAYER,
      nonce,
      gasPrice: BigNumber.from(tx.gasPrice ?? fields.gasPrice ?? 100),
      maxFeePerGas:
        tx.maxFeePerGas === null ? undefined : BigNumber.from(tx.maxFeePerGas),
      maxPriorityFeePerGas:
        tx.maxPriorityFeePerGas === null
          ? undefined
          : BigNumber.from(tx.maxPriorityFeePerGas),
      gasLimit: BigNumber.from(21000),
    };
  };
  const mutate = (change: string) => {
    switch (change) {
      case 'account':
        state.activeAccountId = 1;
        break;
      case 'account type':
        state.activeAccountType = KeyringAccountType.Imported;
        break;
      case 'address':
        state.accounts[state.activeAccountType][0].address =
          otherWallet.address;
        break;
      case 'chain':
        state.activeNetwork.chainId += 1;
        break;
      case 'network kind':
        state.activeNetwork.kind = 'syscoin';
        break;
      case 'RPC':
        state.activeNetwork.url += '/changed';
        break;
      case 'slip44':
        state.activeNetwork.slip44 += 1;
        break;
      case 'provider':
        currentProvider = { ...provider };
        break;
      case 'session':
        session = {};
        break;
      default:
        throw new Error(`Unknown fixture mutation: ${change}`);
    }
  };
  const changes = [
    'account',
    'account type',
    'address',
    'chain',
    'network kind',
    'RPC',
    'slip44',
    'provider',
    'session',
  ];

  beforeEach(() => {
    signed = [];
    session = {};
    hostCurrent = true;
    assertHostContext = () => {
      if (!hostCurrent) throw new Error('Host selection changed');
    };
    state = {
      activeAccountType: KeyringAccountType.HDAccount,
      activeAccountId: 0,
      activeNetwork: {
        chainId: CHAIN,
        kind: 'ethereum',
        slip44: 60,
        currency: 'tsys',
        url: 'https://rpc.invalid',
      },
      accounts: Object.fromEntries(
        accountTypes.map((type) => [
          type,
          { 0: { address: PAYER }, 1: { address: otherWallet.address } },
        ])
      ),
    };
    provider = {
      getTransaction: jest.fn().mockResolvedValue(original()),
      getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(100)),
      getNetwork: jest.fn().mockResolvedValue({ chainId: CHAIN }),
      getTransactionCount: jest.fn().mockResolvedValue(99),
      verifyConfiguredChainId: jest.fn().mockResolvedValue(undefined),
      sendTransaction: jest.fn(async (raw: string) => {
        const tx = Transaction.from(raw);
        signed.push(tx);
        return { hash: tx.hash, from: tx.from, nonce: tx.nonce };
      }),
    };
    currentProvider = provider;
    getKey = jest.fn(() => ({
      address: PAYER,
      decryptedPrivateKey: wallet.privateKey,
    }));
    ledger = {
      evm: {
        signEVMTransaction: jest.fn(async ({ rawTx }) => {
          const signature = deviceSignature(`0x${rawTx}`);
          return {
            r: signature.r.slice(2),
            s: signature.s.slice(2),
            v: signature.v.toString(16),
          };
        }),
      },
    };
    trezor = {
      signEthTransaction: jest.fn(async ({ tx }) => {
        const signature = deviceSignature(tx);
        return {
          success: true,
          payload: { r: signature.r, s: signature.s, v: signature.v },
        };
      }),
    };
    sdk = new EthereumTransactions(
      () => state.activeNetwork,
      getKey,
      () => state,
      ledger,
      trezor,
      () => {
        const captured = session;
        return () => {
          if (captured !== session) throw new Error('Session changed');
        };
      },
      createTestSubmissionCapture()
    );
    Object.defineProperty(sdk, 'web3Provider', {
      get: () => currentProvider,
    });
    jest
      .spyOn(sdk, 'getFeeDataWithDynamicMaxPriorityFeePerGas')
      .mockResolvedValue({
        gasPrice: BigNumber.from(100),
        baseFeePerGas: BigNumber.from(1),
        maxFeePerGas: BigNumber.from(100),
        maxPriorityFeePerGas: BigNumber.from(10),
      });
  });

  afterEach(() => jest.restoreAllMocks());

  it.each(
    accountTypes.flatMap((type) =>
      [true, false].flatMap((legacy) =>
        [0, 7].flatMap((nonce) =>
          [true, false].map((missing) => ({ type, legacy, nonce, missing }))
        )
      )
    )
  )('preserves cancellation payload and exact fees for %j', async (test) => {
    state.activeAccountType = test.type;
    provider.getTransaction.mockResolvedValue(
      test.missing ? null : original(test.nonce, { type: test.legacy ? 0 : 2 })
    );
    sdk.setGasOverrides({ minGasLimit: '99999' });
    const result = await run(test.legacy, test.nonce);
    expect(result.isCanceled).toBe(true);
    expect(signed).toHaveLength(1);
    const tx = signed[0];
    expect(tx.from).toBe(PAYER);
    expect(tx.to).toBe(PAYER);
    expect(tx.nonce).toBe(test.nonce);
    expect(tx.chainId).toBe(BigInt(CHAIN));
    expect(tx.gasLimit).toBe(BigInt(42000));
    expect(tx.value).toBe(BigInt(0));
    expect(tx.data).toBe('0x');
    expect(tx.type).toBe(test.legacy ? 0 : 2);
    if (test.legacy) expect(tx.gasPrice).toBe(BigInt(120));
    else {
      expect(tx.maxFeePerGas).toBe(BigInt(120));
      expect(tx.maxPriorityFeePerGas).toBe(BigInt(12));
    }
    expect(provider.getTransactionCount).not.toHaveBeenCalled();
    if (!test.legacy)
      expect(
        sdk.getFeeDataWithDynamicMaxPriorityFeePerGas
      ).toHaveBeenCalledWith(provider);
    if (
      [KeyringAccountType.Ledger, KeyringAccountType.Trezor].includes(test.type)
    )
      expect(getKey).not.toHaveBeenCalled();
  });

  it.each(changes)(
    'rejects changed %s after original lookup, before any signing',
    async (change) => {
      const held = deferred<any>();
      provider.getTransaction.mockReturnValue(held.promise);
      const result = run();
      const rejected = expect(result).rejects.toThrow();
      mutate(change);
      held.resolve(original());
      await rejected;
      expect(getKey).not.toHaveBeenCalled();
      expect(ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
      expect(trezor.signEthTransaction).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(
    [true, false].flatMap((legacy) =>
      [true, false].map((missing) => ({ legacy, missing }))
    )
  )(
    'rejects a changed session after delayed fee lookup for %j',
    async ({ legacy, missing }) => {
      provider.getTransaction.mockResolvedValue(missing ? null : original());
      const started = deferred<void>();
      const held = deferred<any>();
      const lookup = () => {
        started.resolve();
        return held.promise;
      };
      if (legacy) provider.getGasPrice.mockImplementation(lookup);
      else
        jest
          .mocked(sdk.getFeeDataWithDynamicMaxPriorityFeePerGas)
          .mockImplementation(lookup);
      const result = run(legacy, 7);
      const rejected = expect(result).rejects.toThrow('Session changed');
      await started.promise;
      session = {};
      held.resolve(
        legacy
          ? BigNumber.from(100)
          : {
              maxFeePerGas: BigNumber.from(100),
              maxPriorityFeePerGas: BigNumber.from(10),
            }
      );
      await rejected;
      expect(getKey).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(changes)(
    'rejects changed %s before software signing after provider preflight',
    async (change) => {
      const started = deferred<void>();
      const held = deferred<void>();
      provider.verifyConfiguredChainId.mockImplementation(() => {
        started.resolve();
        return held.promise;
      });
      const result = run();
      await started.promise;
      mutate(change);
      held.resolve();
      expect(await result).toEqual({
        isCanceled: false,
        error: true,
        transactionNotBroadcast: true,
      });
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(
    [KeyringAccountType.Ledger, KeyringAccountType.Trezor].flatMap((type) =>
      changes.map((change) => ({ type, change }))
    )
  )(
    'does not broadcast delayed hardware approval after %j',
    async ({ type, change }) => {
      state.activeAccountType = type;
      const started = deferred<void>();
      const held = deferred<void>();
      const device =
        type === KeyringAccountType.Ledger
          ? ledger.evm.signEVMTransaction
          : trezor.signEthTransaction;
      const implementation = device.getMockImplementation();
      device.mockImplementation(async (params: any) => {
        started.resolve();
        await held.promise;
        return implementation(params);
      });
      const result = run();
      await started.promise;
      mutate(change);
      held.resolve();
      expect(await result).toEqual({
        isCanceled: false,
        error: true,
        transactionNotBroadcast: true,
      });
      expect(provider.sendTransaction).not.toHaveBeenCalled();
      expect(getKey).not.toHaveBeenCalled();
    }
  );

  it('rejects a private-key lookup returning another account', async () => {
    getKey.mockReturnValue({
      address: otherWallet.address,
      decryptedPrivateKey: otherWallet.privateKey,
    });
    expect(await run()).toEqual({
      isCanceled: false,
      error: true,
      transactionNotBroadcast: true,
    });
    expect(provider.verifyConfiguredChainId).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it.each(accountTypes)(
    'retains a %s acknowledged hash when context changes after submission',
    async (type) => {
      state.activeAccountType = type;
      provider.sendTransaction.mockImplementation(async (raw: string) => {
        state.activeNetwork.chainId += 1;
        return { hash: Transaction.from(raw).hash };
      });
      const result = await run();
      expect(result.isCanceled).toBe(true);
      expect(result.transaction?.hash).toMatch(/^0x[\da-f]{64}$/);
    }
  );

  it('preserves missing-original/no-fallback behavior without signing', async () => {
    provider.getTransaction.mockResolvedValue(null);
    expect(await run()).toEqual({
      isCanceled: false,
      error: true,
    });
    expect(getKey).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it.each([true, false])(
    'keeps the one-wei minimum bump (legacy=%s)',
    async (legacy) => {
      provider.getTransaction.mockResolvedValue({
        ...original(7, {
          type: legacy ? 0 : 2,
          gasPrice: BigNumber.from(0),
          maxFeePerGas: BigNumber.from(1),
          maxPriorityFeePerGas: BigNumber.from(0),
        }),
      });
      provider.getGasPrice.mockResolvedValue(BigNumber.from(0));
      jest
        .mocked(sdk.getFeeDataWithDynamicMaxPriorityFeePerGas)
        .mockResolvedValue({
          gasPrice: BigNumber.from(0),
          baseFeePerGas: BigNumber.from(0),
          maxFeePerGas: BigNumber.from(1),
          maxPriorityFeePerGas: BigNumber.from(0),
        });
      expect((await run(legacy)).isCanceled).toBe(true);
      if (legacy) expect(signed[0].gasPrice).toBe(BigInt(1));
      else {
        expect(signed[0].maxFeePerGas).toBe(BigInt(2));
        expect(signed[0].maxPriorityFeePerGas).toBe(BigInt(1));
      }
    }
  );

  it.each([true, false])(
    'retains large integer fee precision (legacy=%s)',
    async (legacy) => {
      const large = BigNumber.from('1000000000000000003');
      provider.getTransaction.mockResolvedValue({
        ...original(7, {
          type: legacy ? 0 : 2,
          gasPrice: large,
          maxFeePerGas: large,
        }),
      });
      expect((await run(legacy)).isCanceled).toBe(true);
      const fee = legacy ? signed[0].gasPrice : signed[0].maxFeePerGas;
      expect(fee).toBe(BigInt('1200000000000000003'));
    }
  );

  it.each([
    { legacy: true, fee: -1 },
    { legacy: true, fee: Number.MAX_SAFE_INTEGER + 1 },
    { legacy: true, fee: 'not-a-fee' },
    { legacy: false, maximum: 0, priority: 0 },
    { legacy: false, maximum: 1, priority: 2 },
    { legacy: false, maximum: 1, priority: -1 },
    { legacy: false, maximum: 'not-a-fee', priority: 0 },
  ])(
    'rejects invalid cancellation fee data %j before signing',
    async (test) => {
      if (test.legacy) provider.getGasPrice.mockResolvedValue(test.fee);
      else {
        jest
          .mocked(sdk.getFeeDataWithDynamicMaxPriorityFeePerGas)
          .mockResolvedValue({
            maxFeePerGas: test.maximum,
            maxPriorityFeePerGas: test.priority,
          } as any);
      }
      await expect(run(test.legacy)).rejects.toThrow();
      expect(getKey).not.toHaveBeenCalled();
      expect(ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
      expect(trezor.signEthTransaction).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(['lookup', 'legacy fee', 'dynamic fee'])(
    'does not sign after %s failure',
    async (step) => {
      const error = new Error('Synthetic unavailable RPC');
      if (step === 'lookup') provider.getTransaction.mockRejectedValue(error);
      if (step === 'legacy fee') provider.getGasPrice.mockRejectedValue(error);
      if (step === 'dynamic fee')
        jest
          .mocked(sdk.getFeeDataWithDynamicMaxPriorityFeePerGas)
          .mockRejectedValue(error);
      await expect(run(step !== 'dynamic fee')).rejects.toBe(error);
      expect(getKey).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
    'preserves %s device rejection without broadcast',
    async (type) => {
      state.activeAccountType = type;
      const device =
        type === KeyringAccountType.Ledger
          ? ledger.evm.signEVMTransaction
          : trezor.signEthTransaction;
      device.mockRejectedValue(new Error('Synthetic device rejection'));
      expect(await run()).toEqual({
        isCanceled: false,
        error: true,
        transactionNotBroadcast: true,
      });
      expect(getKey).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(accountTypes)(
    'checks a host selection hidden by the %s keyring payer selection',
    async (type) => {
      state.activeAccountType = type;
      let hostScope = 'smart-account-a';
      const assertCurrentContext = jest.fn(() => {
        if (hostScope !== 'smart-account-a')
          throw new Error('Host selection changed');
      });
      const entered = deferred<void>();
      const held = deferred<void>();
      provider.getTransaction.mockImplementation(async () => {
        entered.resolve();
        await held.promise;
        return original();
      });
      const pending = sdk.cancelSentTransaction(HASH, true, 7, {
        assertCurrentContext,
        approvedMaximumFee: '9'.repeat(78),
        validateOriginal: () => undefined,
      });
      const rejected = expect(pending).rejects.toThrow(
        'Host selection changed'
      );
      await entered.promise;
      hostScope = 'smart-account-b';
      held.resolve();
      await rejected;
      expect(state.activeAccountType).toBe(type);
      expect(state.activeAccountId).toBe(0);
      expect(assertCurrentContext).toHaveBeenCalled();
      expect(getKey).not.toHaveBeenCalled();
      expect(ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
      expect(trezor.signEthTransaction).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it.each(accountTypes)(
    'keeps a %s acknowledged hash after the host selection changes at submission',
    async (type) => {
      state.activeAccountType = type;
      let current = true;
      provider.sendTransaction.mockImplementation(async (raw: string) => {
        current = false;
        return { hash: Transaction.from(raw).hash };
      });
      const result = await sdk.cancelSentTransaction(HASH, true, 7, {
        approvedMaximumFee: '9'.repeat(78),
        validateOriginal: () => undefined,
        assertCurrentContext: () => {
          if (!current) throw new Error('Host selection changed');
        },
      });
      expect(result.isCanceled).toBe(true);
      expect(result.transaction?.hash).toMatch(/^0x[\da-f]{64}$/);
    }
  );

  it.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
    'checks the host guard after a pending %s device response',
    async (type) => {
      state.activeAccountType = type;
      let current = true;
      const entered = deferred<void>();
      const held = deferred<void>();
      const device =
        type === KeyringAccountType.Ledger
          ? ledger.evm.signEVMTransaction
          : trezor.signEthTransaction;
      const implementation = device.getMockImplementation();
      device.mockImplementation(async (params: any) => {
        entered.resolve();
        await held.promise;
        return implementation(params);
      });
      const pending = sdk.cancelSentTransaction(HASH, true, 7, {
        approvedMaximumFee: '9'.repeat(78),
        validateOriginal: () => undefined,
        assertCurrentContext: () => {
          if (!current) throw new Error('Host selection changed');
        },
      });
      await entered.promise;
      current = false;
      held.resolve();
      expect(await pending).toEqual({
        isCanceled: false,
        error: true,
        transactionNotBroadcast: true,
      });
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it('rejects a Trezor cancellation changed after its unsigned envelope was captured', async () => {
    state.activeAccountType = KeyringAccountType.Trezor;
    const persistSigned = jest.fn(async () => undefined);
    (sdk as any).captureSubmissionLifecycle = () => ({
      assertCurrent: () => undefined,
      persistSigned,
      dispatchSigned: admitTestSignedDispatch,
    });
    trezor.signEthTransaction.mockImplementationOnce(async ({ tx }: any) => {
      tx.value = '0x1';
      return { success: true, payload: deviceSignature(tx) };
    });
    const result = await run();
    expect(result).toMatchObject({
      isCanceled: false,
      error: true,
      transactionNotBroadcast: true,
    });
    expect(trezor.signEthTransaction).toHaveBeenCalledTimes(1);
    expect(persistSigned).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('checks the host guard before private-key signing after provider preflight', async () => {
    let current = true;
    provider.verifyConfiguredChainId.mockImplementation(async () => {
      current = false;
    });
    const result = await sdk.cancelSentTransaction(HASH, true, 7, {
      approvedMaximumFee: '9'.repeat(78),
      validateOriginal: () => undefined,
      assertCurrentContext: () => {
        if (!current) throw new Error('Host selection changed');
      },
    });
    expect(result).toEqual({
      isCanceled: false,
      error: true,
      transactionNotBroadcast: true,
    });
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it.each([
    undefined,
    null,
    {},
    { assertCurrentContext: null },
    { assertCurrentContext: true },
  ])(
    'rejects missing or invalid required host context %p before runtime access',
    async (options) => {
      const capture = jest.spyOn(sdk as any, 'captureEvmSigningContext');
      await expect(
        sdk.cancelSentTransaction(HASH, true, 7, options as any)
      ).rejects.toThrow('Cancellation context required');
      expect(capture).not.toHaveBeenCalled();
      expect(provider.getTransaction).not.toHaveBeenCalled();
      expect(provider.getGasPrice).not.toHaveBeenCalled();
      expect(getKey).not.toHaveBeenCalled();
      expect(ledger.evm.signEVMTransaction).not.toHaveBeenCalled();
      expect(trezor.signEthTransaction).not.toHaveBeenCalled();
      expect(provider.sendTransaction).not.toHaveBeenCalled();
    }
  );

  it('rejects the former three-argument invocation before runtime access', async () => {
    await expect(
      (sdk.cancelSentTransaction as any)(HASH, true, 7)
    ).rejects.toThrow('Cancellation context required');
    expect(provider.getTransaction).not.toHaveBeenCalled();
    expect(getKey).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });

  it('rejects an already-stale explicit host context before runtime access', async () => {
    hostCurrent = false;
    await expect(run()).rejects.toThrow('Host selection changed');
    expect(provider.getTransaction).not.toHaveBeenCalled();
    expect(getKey).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  });
});
