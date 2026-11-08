import { Transaction, Wallet } from 'ethers';

import { evmSubmissionFailure } from '../../../src/transactions/evm-submission';
import { signTrezorEvmTransaction } from '../../../src/transactions/trezor-signing';
import { TrezorKeyring } from '../../../src/trezor';
import { createTrezorConnection } from '../../../src/trezor/connect';
import {
  TREZOR_METHODS,
  type TrezorHost,
} from '../../../src/trezor/host-types';

jest.unmock('../../../src/trezor/connect');

const wallet = new Wallet('0x' + '31'.repeat(32));
const recipient = '0x' + '22'.repeat(20);
const legacy = {
  chainId: 1,
  type: 0,
  nonce: 0,
  to: recipient,
  value: 0,
  gasLimit: 21000,
  gasPrice: 1,
};
const typed = {
  chainId: 324,
  type: 2,
  nonce: 8,
  to: recipient,
  value: 2,
  gasLimit: 90000,
  maxFeePerGas: 3,
  maxPriorityFeePerGas: 1,
  accessList: [
    { address: recipient, storageKeys: ['0x' + '01'.repeat(32)] },
    { address: recipient, storageKeys: [] },
  ],
};

function sign(tx: Record<string, unknown>) {
  const transaction = Transaction.from({
    ...tx,
    type: tx.gasPrice === undefined ? 2 : 0,
  });
  const signature = wallet.signingKey.sign(transaction.unsignedHash);
  return {
    success: true as const,
    payload: {
      r: signature.r,
      s: signature.s,
      v: signature.v.toString(16),
      serializedTx: '',
    },
  };
}
function fixture(transaction: Record<string, unknown> = legacy) {
  const controller = new AbortController();
  const authority = {
    signal: controller.signal,
    assertCurrent: jest.fn(() => undefined),
  };
  const signer = { signEthTransaction: jest.fn(async ({ tx }) => sign(tx)) };
  const request = {
    accountIndex: 4,
    coin: 'eth',
    slip44: 60,
    expectedAddress: wallet.address,
    unsignedTransaction: Transaction.from(transaction).unsignedSerialized,
  };
  return { signer, request, authority, controller };
}

it.each([
  legacy,
  typed,
  { ...typed, to: null, value: 0, data: '0x60806040', accessList: [] },
])(
  'signs exactly the reviewed canonical Trezor envelope',
  async (transaction) => {
    const f = fixture(transaction);
    const result = await signTrezorEvmTransaction(
      f.signer,
      f.request,
      f.authority
    );
    const signed = Transaction.from(result.rawTransaction);
    expect(signed.unsignedSerialized).toBe(f.request.unsignedTransaction);
    expect(signed.from).toBe(wallet.address);
    expect(result.hash).toBe(signed.hash);
    expect(Object.isFrozen(result)).toBe(true);
    const [{ tx, index, coin, slip44 }, owner] =
      f.signer.signEthTransaction.mock.calls[0];
    expect({ index, coin, slip44 }).toEqual({
      index: '4',
      coin: 'eth',
      slip44: 60,
    });
    expect(owner.signal).toBe(f.controller.signal);
    expect(tx.chainId).toBe(transaction.chainId);
    for (const field of ['nonce', 'value', 'gasLimit'])
      expect(typeof tx[field]).toBe('string');
    expect(
      Transaction.from({ ...tx, type: transaction.type }).unsignedSerialized
    ).toBe(f.request.unsignedTransaction);
    if (transaction.type === 2)
      expect(tx.accessList).toEqual(transaction.accessList);
  }
);

it.each([
  undefined,
  {
    signal: new AbortController().signal,
    assertCurrent: async () => undefined,
  },
  { signal: new AbortController().signal, assertCurrent: () => true },
])(
  'requires synchronous current authority before accessing Trezor',
  async (authority) => {
    const f = fixture();
    await expect(
      signTrezorEvmTransaction(f.signer, f.request, authority as any)
    ).rejects.toThrow('no longer current');
    expect(f.signer.signEthTransaction).not.toHaveBeenCalled();
  }
);

it.each([
  { accountIndex: -1 },
  { accountIndex: 0x80000000 },
  { slip44: -1 },
  { slip44: 1.5 },
  { coin: '' },
  { expectedAddress: 'bad address' },
  {
    unsignedTransaction: Transaction.from({
      ...legacy,
      type: 1,
      accessList: [],
    }).unsignedSerialized,
  },
  {
    unsignedTransaction: Transaction.from({ ...legacy, chainId: 0 })
      .unsignedSerialized,
  },
  {
    unsignedTransaction: Transaction.from({
      ...legacy,
      chainId: 9007199254740992n,
    }).unsignedSerialized,
  },
])(
  'rejects invalid reviewed Trezor input before device access',
  async (changes) => {
    const f = fixture();
    await expect(
      signTrezorEvmTransaction(
        f.signer,
        { ...f.request, ...changes },
        f.authority
      )
    ).rejects.toThrow();
    expect(f.signer.signEthTransaction).not.toHaveBeenCalled();
  }
);

it('rejects signed and noncanonical envelopes before device access', async () => {
  const f = fixture();
  const signed = await signTrezorEvmTransaction(
    f.signer,
    f.request,
    f.authority
  );
  f.signer.signEthTransaction.mockClear();
  for (const bytes of [
    signed.rawTransaction,
    f.request.unsignedTransaction.toUpperCase(),
  ]) {
    await expect(
      signTrezorEvmTransaction(
        f.signer,
        { ...f.request, unsignedTransaction: bytes },
        f.authority
      )
    ).rejects.toThrow();
  }
  expect(f.signer.signEthTransaction).not.toHaveBeenCalled();
});

it.each(['numeric', 'hexadecimal', 'prefixed hexadecimal'])(
  'preserves the existing %s signature recovery encoding',
  async (encoding) => {
    const f = fixture();
    f.signer.signEthTransaction.mockImplementation(async ({ tx }) => {
      const result = sign(tx);
      return {
        ...result,
        payload: {
          ...result.payload,
          v:
            encoding === 'numeric'
              ? parseInt(result.payload.v, 16)
              : encoding === 'hexadecimal'
              ? result.payload.v
              : `0x${result.payload.v}`,
        },
      } as any;
    });
    await expect(
      signTrezorEvmTransaction(f.signer, f.request, f.authority)
    ).resolves.toHaveProperty('hash');
  }
);

it.each([{ r: '0x1' }, { s: 'no' }, { v: '0xzz' }, { v: -1 }, { v: 1.5 }])(
  'rejects malformed signature fields',
  async (field) => {
    const f = fixture();
    f.signer.signEthTransaction.mockImplementation(async ({ tx }) => {
      const result = sign(tx);
      return { ...result, payload: { ...result.payload, ...field } } as any;
    });
    await expect(
      signTrezorEvmTransaction(f.signer, f.request, f.authority)
    ).rejects.toThrow();
  }
);

it('rejects a different signer and a device-mutated transaction', async () => {
  const f = fixture(typed);
  const mismatch = await signTrezorEvmTransaction(
    f.signer,
    { ...f.request, expectedAddress: recipient },
    f.authority
  ).catch((failure) => failure);
  expect(mismatch).toMatchObject({ code: 'HARDWARE_ACCOUNT_MISMATCH' });
  expect(mismatch.signedTransactionHash).toBeUndefined();
  expect(evmSubmissionFailure(mismatch)).toEqual({
    transactionNotBroadcast: true,
  });
  f.signer.signEthTransaction.mockImplementation(async ({ tx }) => {
    tx.accessList[0].storageKeys[0] = '0x' + '02'.repeat(32);
    return sign(tx);
  });
  await expect(
    signTrezorEvmTransaction(f.signer, f.request, f.authority)
  ).rejects.toMatchObject({ code: 'HARDWARE_ACCOUNT_MISMATCH' });
});

it('rejects a valid signature after the caller cancels during device signing', async () => {
  const f = fixture();
  let release!: (result: ReturnType<typeof sign>) => void;
  f.signer.signEthTransaction.mockImplementation(
    ({ tx }) =>
      new Promise((resolve) => {
        release = () => resolve(sign(tx));
      })
  );
  const pending = signTrezorEvmTransaction(f.signer, f.request, f.authority);
  f.controller.abort();
  release(sign(legacy));
  const error = await pending.catch((failure) => failure);
  expect(error).toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  expect(evmSubmissionFailure(error)).toEqual({
    transactionNotBroadcast: true,
  });
});

it('classifies a local Trezor rejection without trusting forged stage fields', async () => {
  const f = fixture();
  const cause = Object.freeze(
    Object.assign(new Error('Device rejected signing'), {
      code: 'DEVICE_REJECTED',
      transactionNotBroadcast: false,
      signedTransactionHash: '0x' + 'ff'.repeat(32),
    })
  );
  f.signer.signEthTransaction.mockRejectedValueOnce(cause);
  const error = await signTrezorEvmTransaction(
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

it('uses the same explicit Trezor host, derivation and final host guard', async () => {
  jest.useFakeTimers();
  const f = fixture(typed);
  const host = {
    ...Object.fromEntries(TREZOR_METHODS.map((method) => [method, jest.fn()])),
    init: jest.fn(async () => undefined),
    dispose: jest.fn(async (pending) => {
      await Promise.allSettled(pending);
    }),
    ethereumSignTransaction: jest.fn(async (assertCurrent, request) => {
      assertCurrent();
      expect(request.path).toBe("m/44'/60'/0'/0/4");
      return sign(request.transaction);
    }),
  } as TrezorHost;
  const connection = createTrezorConnection(host);
  const signer = Object.create(TrezorKeyring.prototype);
  signer.connection = connection;
  signer.executeWithRetry = (operation: () => Promise<unknown>) => operation();
  try {
    await connection.init();
    const pending = signTrezorEvmTransaction(signer, f.request, f.authority);
    await jest.advanceTimersByTimeAsync(2000);
    const result = await pending;
    expect(Transaction.from(result.rawTransaction).unsignedSerialized).toBe(
      f.request.unsignedTransaction
    );
    expect(host.ethereumSignTransaction).toHaveBeenCalledTimes(1);
  } finally {
    await connection.dispose();
    jest.useRealTimers();
  }
});
