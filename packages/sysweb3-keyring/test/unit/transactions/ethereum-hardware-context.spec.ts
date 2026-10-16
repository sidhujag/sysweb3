import { Interface } from 'ethers/abi';
import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { serializeTransaction } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { KeyringAccountType } from '../../../src/types';

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
      sdk.sendFormattedTransaction(request(legacy), legacy);

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
        }
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
        const signing = sdk.sendFormattedTransaction(params, false);
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

    describe.each([
      [
        'ERC20 zero decimals',
        'sendSignedErc20Transaction',
        'transfer(address,uint256)',
        ['2'],
        0,
      ],
      [
        'ERC20 eight decimals',
        'sendSignedErc20Transaction',
        'transfer(address,uint256)',
        ['200000001'],
        8,
      ],
      [
        'ERC721 large id',
        'sendSignedErc721Transaction',
        'transferFrom(address,address,uint256)',
        ['9007199254740993'],
        0,
      ],
      [
        'ERC1155 large integer',
        'sendSignedErc1155Transaction',
        'safeTransferFrom(address,address,uint256,uint256,bytes)',
        ['9007199254740993'],
        0,
      ],
    ] as const)(
      '%s token approval',
      (_name, method, fragment, [atomic], decimals) => {
        const tokenAddress = `0x${'44'.repeat(20)}`;
        const sendToken = (legacy = false) => {
          // Model the old hardware getter's real empty-key return, not a fake
          // software key. New code must not ask for it on hardware routes at all.
          getKey.mockReturnValue({
            address: wallet.address,
            decryptedPrivateKey: softwareUsed ? wallet.privateKey : '',
          });
          return sdk[method]({
            tokenAddress,
            receiver: recipient,
            tokenAmount:
              method === 'sendSignedErc1155Transaction'
                ? atomic
                : decimals === 8
                ? '2.00000001'
                : '2',
            tokenId: '9007199254740993',
            decimals,
            gasLimit: '200000',
            isLegacy: legacy,
            ...(legacy
              ? { gasPrice: '100' }
              : { maxFeePerGas: '100', maxPriorityFeePerGas: '2' }),
          });
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
