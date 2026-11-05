import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { sendLocalEvmTransaction } from '../../../src/transactions/evm-local-signer';
import {
  assertSignedEvmTransactionMatches,
  captureEvmSubmission,
  submitSignedEvmTransaction,
} from '../../../src/transactions/evm-submission';

const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const recipient = `0x${'22'.repeat(20)}`;
const slot = `0x${'33'.repeat(32)}`;
const envelope = (type: number, creation = false) => ({
  type,
  chainId: 7654321,
  nonce: 0,
  to: creation ? null : recipient,
  value: 123n,
  gasLimit: 100000n,
  data: creation ? '0x6000' : '0x1234',
  ...(type === 2
    ? { maxFeePerGas: 10n, maxPriorityFeePerGas: 2n }
    : { gasPrice: 10n }),
  ...(type === 0
    ? {}
    : { accessList: [{ address: recipient, storageKeys: [slot] }] }),
});
const context = {
  account: { id: 0, type: 'HDAccount', address: wallet.address },
  network: {
    kind: 'ethereum',
    chainId: 7654321,
    slip44: 60,
    url: 'https://offline.invalid',
  },
  operation: 'send' as const,
};

it.each([0, 1, 2])(
  'accepts exact type %i bytes, including contract creation and access lists',
  async (type) => {
    for (const creation of [false, true]) {
      const request = envelope(type, creation);
      const raw = await wallet.signTransaction(request);
      const expected = Transaction.from(request).unsignedSerialized;
      expect(
        assertSignedEvmTransactionMatches(raw, expected, wallet.address).hash
      ).toBe(Transaction.from(raw).hash);
    }
  }
);

it.each([
  ['nonce', { nonce: 7 }],
  ['recipient', { to: wallet.address }],
  ['value', { value: 124n }],
  ['gas', { gasLimit: 100001n }],
  ['data', { data: '0x1235' }],
  ['maximum fee', { maxFeePerGas: 11n }],
  ['priority fee', { maxPriorityFeePerGas: 3n }],
  [
    'access list',
    {
      accessList: [
        { address: recipient, storageKeys: [`0x${'44'.repeat(32)}`] },
      ],
    },
  ],
])(
  'rejects changed %s before persistence or dispatch',
  async (_name, change) => {
    const request = envelope(2);
    const raw = await wallet.signTransaction({ ...request, ...change });
    const persistSigned = jest.fn(async () => undefined),
      broadcast = jest.fn();
    const boundary = captureEvmSubmission(
      context,
      () => undefined,
      () => ({ assertCurrent: () => undefined, persistSigned })
    );
    await expect(
      submitSignedEvmTransaction(
        raw,
        broadcast,
        boundary,
        undefined,
        Transaction.from(request).unsignedSerialized
      )
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
    expect(persistSigned).not.toHaveBeenCalled();
    expect(broadcast).not.toHaveBeenCalled();
  }
);

it('requires a captured durable lifecycle even with valid approved bytes', async () => {
  const request = envelope(0),
    raw = await wallet.signTransaction(request);
  const broadcast = jest.fn();
  await expect(
    submitSignedEvmTransaction(
      raw,
      broadcast,
      undefined as never,
      undefined,
      Transaction.from(request).unsignedSerialized
    )
  ).rejects.toThrow('captured durable EVM submission is required');
  expect(broadcast).not.toHaveBeenCalled();
});

it.each([0, 1, 2])(
  'the existing software sender persists and dispatches exact type %i bytes',
  async (type) => {
    const request = envelope(type, true);
    const events: string[] = [];
    const boundary = captureEvmSubmission(
      context,
      () => undefined,
      () => ({
        assertCurrent: () => undefined,
        async persistSigned(record) {
          events.push('persist');
          expect(
            Transaction.from(record.rawTransaction).unsignedSerialized
          ).toBe(Transaction.from(request).unsignedSerialized);
        },
      })
    );
    const provider = {
      verifyConfiguredChainId: jest.fn(async () => undefined),
      sendTransaction: jest.fn(async (raw: string) => {
        events.push('dispatch');
        return { hash: Transaction.from(raw).hash };
      }),
    };
    await sendLocalEvmTransaction(
      provider as any,
      wallet.privateKey,
      request,
      undefined,
      undefined,
      undefined,
      boundary
    );
    expect(events).toEqual(['persist', 'dispatch']);
    expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
  }
);
