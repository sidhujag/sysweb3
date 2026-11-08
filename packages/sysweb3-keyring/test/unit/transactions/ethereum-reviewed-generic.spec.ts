import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { serializeTransaction } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { serializePreparedEvmTransaction } from '../../../src/transactions/evm-envelope';
import { KeyringAccountType } from '../../../src/types';
import { withEvmSendIdentity } from '../../helpers/evm-send-identity';
import { admitTestSignedDispatch } from '../../helpers/evm-submission';

import type { EvmSubmissionContext } from '../../../src/transactions/evm-submission';

const wallet = new Wallet(`0x${'19'.repeat(32)}`);
const network = {
  kind: 'ethereum',
  chainId: 743211,
  slip44: 60,
  url: 'https://rpc.invalid',
} as const;
const request = (legacy = false) => ({
  from: wallet.address,
  to: `0x${'22'.repeat(20)}`,
  chainId: String(network.chainId),
  nonce: '7',
  value: '0',
  data: '0x12345678',
  gasLimit: '65000',
  ...(legacy
    ? { type: 0 as const, gasPrice: '99' }
    : {
        type: 2 as const,
        maxFeePerGas: '99',
        maxPriorityFeePerGas: '1',
        accessList: [
          { address: wallet.address, storageKeys: [`0x${'33'.repeat(32)}`] },
        ],
      }),
});

function fixture(kind: KeyringAccountType = KeyringAccountType.HDAccount) {
  const stages: string[] = [];
  const provider = {
    verifyConfiguredChainId: jest.fn(async () => undefined),
    sendTransaction: jest.fn(async (raw: string) => {
      stages.push('broadcast');
      return Transaction.from(raw);
    }),
  };
  const persistSigned = jest.fn(async () => {
    stages.push('persist');
  });
  const capture = jest.fn((context: EvmSubmissionContext) => {
    expect(context.account.address).toBe(wallet.address);
    return {
      assertCurrent: () => undefined,
      persistSigned,
      dispatchSigned: admitTestSignedDispatch,
    };
  });
  const key = jest.fn(() => ({
    address: wallet.address,
    decryptedPrivateKey: wallet.privateKey,
  }));
  const device = jest.fn((raw: string) =>
    wallet.signingKey.sign(Transaction.from(raw).unsignedHash)
  );
  const ledger: any = {
    evm: {
      signEVMTransaction: jest.fn(async ({ rawTx }) => {
        const signature = device(`0x${rawTx}`);
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
      const signature = device(
        serializeTransaction({ ...tx, type: tx.gasPrice === undefined ? 2 : 0 })
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
  const sdk = new EthereumTransactions(
    () => network as any,
    key,
    () =>
      ({
        activeNetwork: network,
        activeAccountId: 0,
        activeAccountType: kind,
        accounts: { [kind]: { 0: { address: wallet.address } } },
      } as any),
    ledger,
    trezor,
    () => () => undefined,
    capture
  );
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  const options = () =>
    withEvmSendIdentity(sdk, {
      mode: 'reviewed-generic' as const,
      reviewId: 'review-one',
      walletNonce: { nonce: 7, source: 'manual' as const },
      assertCurrent: () => undefined,
    });
  return {
    sdk,
    options,
    capture,
    provider,
    persistSigned,
    key,
    device,
    stages,
  };
}

describe.each([
  KeyringAccountType.HDAccount,
  KeyringAccountType.Imported,
  KeyringAccountType.Ledger,
  KeyringAccountType.Trezor,
])('reviewed generic %s', (kind) => {
  test.each([false, true])(
    'preserves all approved bytes and nonce through existing signer, legacy=%s',
    async (legacy) => {
      const f = fixture(kind),
        input = request(legacy);
      const response = (await f.sdk.sendFormattedTransaction(
        input,
        legacy,
        f.options()
      )) as Transaction;
      const expected = Transaction.from(
        serializePreparedEvmTransaction(input)
      ).unsignedHash;
      expect(response.unsignedHash).toBe(expected);
      expect(f.capture.mock.calls[0][0].review).toEqual({
        id: 'review-one',
        unsignedHash: expected,
      });
      expect(f.stages).toEqual(['persist', 'broadcast']);
      expect(response.nonce).toBe(7);
      if (
        kind === KeyringAccountType.Ledger ||
        kind === KeyringAccountType.Trezor
      ) {
        expect(f.key).not.toHaveBeenCalled();
        expect(f.device).toHaveBeenCalledTimes(1);
      }
    }
  );

  test('preserves an exactly reviewed zero-fee type2 envelope', async () => {
    const f = fixture(kind);
    const input = {
      ...request(),
      type: 2 as const,
      maxFeePerGas: '0',
      maxPriorityFeePerGas: '0',
      accessList: [],
    };
    const response = (await f.sdk.sendFormattedTransaction(
      input,
      false,
      f.options()
    )) as Transaction;
    expect(response.maxFeePerGas).toBe(0n);
    expect(response.maxPriorityFeePerGas).toBe(0n);
    expect(response.unsignedHash).toBe(
      Transaction.from(serializePreparedEvmTransaction(input)).unsignedHash
    );
  });
});

test.each([undefined, '', 'space here', 'x'.repeat(129)])(
  'requires a bounded issued review ID %p',
  async (reviewId) => {
    const f = fixture();
    await expect(
      f.sdk.sendFormattedTransaction(request(), false, {
        ...f.options(),
        reviewId,
      } as any)
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    expect(f.capture).not.toHaveBeenCalled();
    expect(f.key).not.toHaveBeenCalled();
  }
);

test('requires the exact approved nonce and a complete envelope before lifecycle capture', async () => {
  const f = fixture();
  for (const [input, options] of [
    [{ ...request(), nonce: '8' }, f.options()],
    [{ ...request(), gasLimit: undefined }, f.options()],
    [request(), { ...f.options(), walletNonce: undefined }],
  ])
    await expect(
      f.sdk.sendFormattedTransaction(input as any, false, options as any)
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
  expect(f.capture).not.toHaveBeenCalled();
  expect(f.key).not.toHaveBeenCalled();
});

test('captures review ID and envelope before an awaited chain probe', async () => {
  const f = fixture();
  let release!: () => void;
  f.provider.verifyConfiguredChainId.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      })
  );
  const input = request(),
    options = f.options();
  const sending = f.sdk.sendFormattedTransaction(input, false, options);
  input.data = '0x5678';
  options.reviewId = 'other-review';
  // Software signing first resolves already captured request properties.
  for (let i = 0; i < 10 && !release; i++) await Promise.resolve();
  release();
  const response = (await sending) as Transaction;
  expect(response.data).toBe('0x12345678');
  expect(f.capture.mock.calls[0][0].review.id).toBe('review-one');
});

test('the host rejects a different issued review before signing', async () => {
  const f = fixture();
  f.capture.mockImplementation((context) => {
    if (context.review?.id !== 'review-one') throw new Error('Unknown review');
    return {
      assertCurrent: () => undefined,
      persistSigned: f.persistSigned,
      dispatchSigned: admitTestSignedDispatch,
    };
  });
  await expect(
    f.sdk.sendFormattedTransaction(request(), false, {
      ...f.options(),
      reviewId: 'different-issued-review',
    })
  ).rejects.toMatchObject({
    transactionNotBroadcast: true,
    message: 'Unknown review',
  });
  expect(f.key).not.toHaveBeenCalled();
  expect(f.provider.sendTransaction).not.toHaveBeenCalled();
});
