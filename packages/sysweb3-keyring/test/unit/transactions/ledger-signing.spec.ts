import { Transaction, Wallet } from 'ethers';

import { evmSubmissionFailure } from '../../../src/transactions/evm-submission';
import { signLedgerEvmTransaction } from '../../../src/transactions/ledger-signing';

const wallet = new Wallet('0x' + '31'.repeat(32));
const from = wallet.address;
const to = '0x' + '22'.repeat(20);

function fixture(transaction: Record<string, unknown>) {
  const unsignedTransaction = Transaction.from(transaction).unsignedSerialized;
  const controller = new AbortController();
  const authority = {
    signal: controller.signal,
    assertCurrent: jest.fn(() => undefined),
  };
  const signer = {
    evm: {
      signEVMTransaction: jest.fn(async (request) => {
        const tx = Transaction.from(`0x${request.rawTx}`);
        const signature = wallet.signingKey.sign(tx.unsignedHash);
        return {
          r: signature.r.slice(2),
          s: signature.s.slice(2),
          v: signature.v.toString(16),
        };
      }),
    },
  };
  const request = {
    accountIndex: 4,
    expectedAddress: from,
    unsignedTransaction,
  };
  return { signer, request, authority, controller };
}

it.each([
  {
    chainId: 57,
    type: 0,
    nonce: 7,
    to,
    value: 1,
    gasLimit: 21000,
    gasPrice: 2,
  },
  {
    chainId: 324,
    type: 2,
    nonce: 8,
    to,
    value: 2,
    gasLimit: 90000,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 1,
    accessList: [
      { address: to, storageKeys: ['0x' + '01'.repeat(32)] },
      { address: to, storageKeys: [] },
    ],
  },
  {
    chainId: 1,
    type: 2,
    nonce: 9,
    to: null,
    data: '0x60806040',
    value: 0,
    gasLimit: 100000,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 0,
    accessList: [],
  },
])(
  'preserves every approved field in a shared Ledger envelope',
  async (transaction) => {
    const f = fixture(transaction);
    const result = await signLedgerEvmTransaction(
      f.signer,
      f.request,
      f.authority
    );
    const signed = Transaction.from(result.rawTransaction);
    expect(signed.unsignedSerialized).toBe(f.request.unsignedTransaction);
    expect(signed.from).toBe(from);
    expect(result.hash).toBe(signed.hash);
    expect(f.signer.evm.signEVMTransaction).toHaveBeenCalledWith(
      {
        accountIndex: 4,
        expectedAddress: from,
        rawTx: f.request.unsignedTransaction.slice(2),
      },
      expect.objectContaining({
        signal: f.controller.signal,
        assertCurrent: expect.any(Function),
      })
    );
  }
);

it('requires a synchronous authority before asking Ledger to sign', async () => {
  const f = fixture({
    chainId: 1,
    type: 0,
    nonce: 0,
    to,
    gasLimit: 21000,
    gasPrice: 1,
  });
  await expect(
    signLedgerEvmTransaction(f.signer, f.request, {
      ...f.authority,
      assertCurrent: (async () => undefined) as any,
    })
  ).rejects.toThrow('no longer current');
  expect(f.signer.evm.signEVMTransaction).not.toHaveBeenCalled();
});

it('discards a valid signature returned after its approval is cancelled', async () => {
  const f = fixture({
    chainId: 1,
    type: 0,
    nonce: 0,
    to,
    gasLimit: 21000,
    gasPrice: 1,
  });
  const sign = f.signer.evm.signEVMTransaction.getMockImplementation()!;
  f.signer.evm.signEVMTransaction.mockImplementation(async (...args) => {
    const result = await sign(...args);
    f.controller.abort();
    return result;
  });
  const error = await signLedgerEvmTransaction(
    f.signer,
    f.request,
    f.authority
  ).catch((failure) => failure);
  expect(error.message).toContain('no longer current');
  expect(evmSubmissionFailure(error)).toEqual({
    transactionNotBroadcast: true,
  });
});

it('rejects a different device key and pre-signed input', async () => {
  const f = fixture({
    chainId: 1,
    type: 0,
    nonce: 0,
    to,
    gasLimit: 21000,
    gasPrice: 1,
  });
  const mismatch = await signLedgerEvmTransaction(
    f.signer,
    { ...f.request, expectedAddress: to },
    f.authority
  ).catch((failure) => failure);
  expect(mismatch.message).toContain('does not match');
  expect(mismatch.signedTransactionHash).toBeUndefined();
  expect(evmSubmissionFailure(mismatch)).toEqual({
    transactionNotBroadcast: true,
  });
  const signed = await signLedgerEvmTransaction(
    f.signer,
    f.request,
    f.authority
  );
  f.signer.evm.signEVMTransaction.mockClear();
  await expect(
    signLedgerEvmTransaction(
      f.signer,
      { ...f.request, unsignedTransaction: signed.rawTransaction },
      f.authority
    )
  ).rejects.toThrow('canonical unsigned');
  expect(f.signer.evm.signEVMTransaction).not.toHaveBeenCalled();
});

it('classifies a local Ledger rejection without trusting forged stage fields', async () => {
  const f = fixture({
    chainId: 1,
    type: 0,
    nonce: 0,
    to,
    gasLimit: 21000,
    gasPrice: 1,
  });
  const cause = Object.freeze(
    Object.assign(new Error('Device rejected signing'), {
      code: 'DEVICE_REJECTED',
      transactionNotBroadcast: false,
      signedTransactionHash: '0x' + 'ff'.repeat(32),
    })
  );
  f.signer.evm.signEVMTransaction.mockRejectedValueOnce(cause);
  const error = await signLedgerEvmTransaction(
    f.signer,
    f.request,
    f.authority
  ).catch((failure) => failure);
  expect(error).toMatchObject({
    code: 'DEVICE_REJECTED',
    transactionNotBroadcast: true,
  });
  expect(error.signedTransactionHash).toBeUndefined();
  expect(evmSubmissionFailure(error)).toEqual({
    transactionNotBroadcast: true,
  });
  expect(evmSubmissionFailure(cause)).toBeUndefined();
});
