// Reload the shared setup's SDK imports so this file uses its real provider response wrapper.
jest.resetModules();
(global as any).window.location = { href: 'http://localhost/' };

import { Interface, Wallet, Transaction } from 'ethers';

import { BigNumber, serializeTransaction } from '../../../src/ethers-v6';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { evmSubmissionFailure } from '../../../src/transactions/evm-submission';
import { KeyringAccountType } from '../../../src/types';

import type {
  CaptureEvmSubmission,
  EvmSignedSubmission,
} from '../../../src/transactions/evm-submission';

const specializedApproval = {
  mode: 'specialized' as const,
  assertCurrent: () => undefined,
};

jest.mock('../../../src/providers', () => ({
  ...jest.requireActual('../../../src/providers'),
  CustomJsonRpcProvider: jest.fn(),
}));

jest.mock('../../../src/ethers-v6', () => {
  const actual = jest.requireActual('../../../src/ethers-v6');
  const { Interface } = jest.requireActual('ethers');
  const erc20 = new Interface(['function transfer(address,uint256)']);
  return {
    ...actual,
    Contract: jest.fn().mockImplementation((address) => ({
      interface: {
        encodeFunctionData: (method: string, args: unknown[]) => {
          if (method !== 'transfer') return '0x12345678';
          return erc20.encodeFunctionData(method, args);
        },
      },
      transfer: {
        populateTransaction: async (
          to: string,
          amount: bigint,
          overrides: any
        ) => ({
          to: address,
          data: erc20.encodeFunctionData('transfer', [to, amount]),
          ...overrides,
        }),
      },
      transferFrom: {
        populateTransaction: async (
          _from: any,
          _to: any,
          _id: any,
          overrides: any
        ) => ({ to: address, data: '0x12345678', ...overrides }),
      },
      safeTransferFrom: {
        populateTransaction: async (
          _from: any,
          _to: any,
          _id: any,
          _amount: any,
          _data: any,
          overrides: any
        ) => ({ to: address, data: '0x12345678', ...overrides }),
      },
    })),
  };
});

const key = `0x${'11'.repeat(32)}`,
  wallet = new Wallet(key),
  to = `0x${'22'.repeat(20)}`;
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};
const kinds = [
  KeyringAccountType.HDAccount,
  KeyringAccountType.Imported,
  KeyringAccountType.Ledger,
  KeyringAccountType.Trezor,
];
const operations = [
  'send',
  'cancel',
  'speed-up',
  'erc20',
  'erc721',
  'erc1155',
] as const;
function fixture(kind: KeyringAccountType, capture?: CaptureEvmSubmission) {
  const network = {
    kind: 'ethereum',
    chainId: 7654321,
    slip44: 60,
    url: 'https://offline.invalid',
    currency: 'eth',
  } as any;
  const state: any = {
    activeAccountType: kind,
    activeAccountId: 0,
    activeNetwork: network,
    accounts: { [kind]: { 0: { address: wallet.address } } },
  };
  let sessionCurrent = true;
  const device = jest.fn(async (raw: string) =>
    wallet.signingKey.sign(Transaction.from(raw).unsignedHash)
  );
  const ledger: any = {
    evm: {
      signEVMTransaction: jest.fn(async ({ rawTx }) => {
        const sig = await device(`0x${rawTx}`);
        return { r: sig.r.slice(2), s: sig.s.slice(2), v: sig.v.toString(16) };
      }),
    },
  };
  const trezor: any = {
    signEthTransaction: jest.fn(async ({ tx }) => ({
      success: true,
      payload: await device(
        serializeTransaction({ ...tx, type: tx.gasPrice !== undefined ? 0 : 2 })
      ),
    })),
  };
  const keyAccess = jest.fn(() => ({
    address: wallet.address,
    decryptedPrivateKey: key,
  }));
  const sdk = new EthereumTransactions(
    () => network,
    keyAccess,
    () => state,
    ledger,
    trezor,
    () => () => {
      if (!sessionCurrent) throw Error('session locked');
    },
    capture ?? null
  );
  const provider: any = {
    verifyConfiguredChainId: jest.fn(async () => undefined),
    getNetwork: jest.fn(async () => ({ chainId: network.chainId })),
    getTransactionCount: jest.fn(async () => 7),
    getBalance: jest.fn(async () => BigNumber.from('1000000000000000000')),
    getFeeData: jest.fn(async () => ({
      gasPrice: BigNumber.from(2),
      maxFeePerGas: BigNumber.from(3),
      maxPriorityFeePerGas: BigNumber.from(1),
    })),
    getGasPrice: jest.fn(async () => BigNumber.from(2)),
    getBlock: jest.fn(async () => ({ baseFeePerGas: BigNumber.from(1) })),
    estimateGas: jest.fn(async () => BigNumber.from(42000)),
    send: jest.fn(async () => '0x1'),
    sendTransaction: jest.fn(async (raw: string) => ({
      hash: Transaction.from(raw).hash,
    })),
    getTransaction: jest.fn(),
  };
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  const original = wallet.signTransaction({
    to,
    value: 123,
    nonce: 7,
    chainId: network.chainId,
    type: 2,
    gasLimit: 42000,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 1,
  });
  const submit = async (
    operation: (typeof operations)[number],
    previewOnly = false,
    saveTrezorTx?: () => void,
    needsGasEstimate = false
  ) => {
    const originalTx = Transaction.from(await original);
    provider.getTransaction.mockResolvedValue({
      ...originalTx.toJSON(),
      signature: originalTx.signature,
      hash: originalTx.hash,
      from: originalTx.from,
      blockNumber: null,
    });
    const options = {
      previewOnly,
      approvedMaximumFee: '1000000000',
      assertCurrentContext: () => undefined,
      validateOriginal: () => undefined,
    };
    if (operation === 'cancel')
      return sdk.cancelSentTransaction(originalTx.hash!, false, 7, options);
    if (operation === 'speed-up')
      return sdk.sendTransactionWithEditedFee(originalTx.hash!, false, options);
    if (operation === 'send')
      return sdk.sendFormattedTransaction(
        {
          from: wallet.address,
          to,
          chainId: network.chainId,
          value: 123,
          nonce: 7,
          gasLimit: needsGasEstimate ? undefined : 42000,
          maxFeePerGas: 3,
          maxPriorityFeePerGas: 1,
        } as any,
        false,
        specializedApproval
      );
    const request = {
      networkUrl: network.url,
      saveTrezorTx,
      receiver: to,
      tokenAddress: to,
      gasLimit: 42000,
      maxFeePerGas: 3,
      maxPriorityFeePerGas: 1,
    };
    if (operation === 'erc20')
      return sdk.sendSignedErc20Transaction({
        ...request,
        tokenAmountUnits: '1',
      });
    if (operation === 'erc721')
      return sdk.sendSignedErc721Transaction({ ...request, tokenId: '1' });
    return sdk.sendSignedErc1155Transaction({
      ...request,
      tokenId: '1',
      tokenAmount: '1',
    });
  };
  return {
    sdk,
    state,
    network,
    provider,
    device,
    keyAccess,
    submit,
    lock: () => {
      sessionCurrent = false;
    },
  };
}

afterEach(() => jest.restoreAllMocks());
for (const kind of kinds)
  for (const operation of operations) {
    it(`${kind} ${operation} waits for exact-byte persistence before its single dispatch`, async () => {
      const entered = deferred(),
        ack = deferred();
      let saved!: EvmSignedSubmission;
      const capture = jest.fn(() => ({
        assertCurrent() {
          return undefined;
        },
        async persistSigned(record: EvmSignedSubmission) {
          saved = record;
          entered.resolve();
          await ack.promise;
        },
      }));
      const f = fixture(kind, capture),
        result = f.submit(operation);
      await Promise.race([
        entered.promise,
        result.then((value) => {
          throw new Error(
            `Completed before persistence: ${JSON.stringify(value)}`
          );
        }),
      ]);
      expect(f.provider.sendTransaction).not.toHaveBeenCalled();
      expect(saved.context.operation).toBe(operation);
      expect(saved.context.account.type).toBe(kind);
      expect(saved.context.account.address).toBe(wallet.address);
      expect(saved.rawTransaction).not.toContain(key);
      expect(Object.isFrozen(saved)).toBe(true);
      ack.resolve();
      await result;
      expect(capture).toHaveBeenCalledTimes(1);
      expect(f.provider.sendTransaction).toHaveBeenCalledTimes(1);
      expect(f.provider.sendTransaction).toHaveBeenCalledWith(
        saved.rawTransaction
      );
    });
    it(`${kind} ${operation} refuses a session revoked while storage acknowledges`, async () => {
      const entered = deferred(),
        ack = deferred();
      let saved = '';
      const f = fixture(kind, () => ({
        assertCurrent() {
          return undefined;
        },
        async persistSigned(record) {
          saved = record.rawTransaction;
          entered.resolve();
          await ack.promise;
        },
      }));
      const result = f.submit(operation).catch((e) => e);
      await Promise.race([
        entered.promise,
        result.then((value) => {
          throw new Error(
            `Completed before persistence: ${JSON.stringify(value)}`
          );
        }),
      ]);
      f.lock();
      ack.resolve();
      const outcome = await result;
      expect(saved).toMatch(/^0x/);
      expect(f.provider.sendTransaction).not.toHaveBeenCalled();
      expect(
        operation === 'cancel' || operation === 'speed-up' ? outcome : outcome
      ).toMatchObject({ transactionNotBroadcast: true });
    });
  }

it('keeps exact ERC20 amounts on the ERC20 capture and persistence route', async () => {
  const nonceRead = deferred();
  const nonceReady = deferred();
  const stored = deferred();
  const acknowledged = deferred();
  let saved!: EvmSignedSubmission;
  const capture = jest.fn(() => ({
    assertCurrent: () => undefined,
    async persistSigned(record: EvmSignedSubmission) {
      saved = record;
      stored.resolve();
      await acknowledged.promise;
    },
  }));
  const { sdk, network, provider } = fixture(
    KeyringAccountType.HDAccount,
    capture
  );
  provider.getTransactionCount.mockImplementationOnce(async () => {
    nonceRead.resolve();
    await nonceReady.promise;
    return 7;
  });
  const sending = sdk.sendSignedErc20Transaction({
    networkUrl: network.url,
    receiver: to,
    tokenAddress: to,
    tokenAmountUnits: '9007199254740993',
    gasLimit: 42000,
    maxFeePerGas: 3,
    maxPriorityFeePerGas: 1,
  });
  await Promise.race([nonceRead.promise, sending]);
  expect(capture).toHaveBeenCalledWith(
    expect.objectContaining({ operation: 'erc20' })
  );
  expect(provider.sendTransaction).not.toHaveBeenCalled();
  nonceReady.resolve();
  await Promise.race([stored.promise, sending]);
  expect(saved.context.operation).toBe('erc20');
  const tx = Transaction.from(saved.rawTransaction);
  const transfer = new Interface(['function transfer(address,uint256)']);
  expect(Array.from(transfer.decodeFunctionData('transfer', tx.data))).toEqual([
    to,
    9007199254740993n,
  ]);
  expect(provider.sendTransaction).not.toHaveBeenCalled();
  acknowledged.resolve();
  await sending;
  expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
  expect(provider.sendTransaction).toHaveBeenCalledWith(saved.rawTransaction);
});

it.each(operations)(
  'refuses %s without durable authority before RPC or signer entry',
  async (operation) => {
    const f = fixture(KeyringAccountType.HDAccount);
    await expect(f.submit(operation)).rejects.toThrow(
      'durable EVM submission lifecycle is required'
    );
    for (const method of Object.values(f.provider))
      expect(method).not.toHaveBeenCalled();
    expect(f.keyAccess).not.toHaveBeenCalled();
    expect(f.device).not.toHaveBeenCalled();
  }
);

it.each([
  KeyringAccountType.HDAccount,
  KeyringAccountType.Ledger,
  KeyringAccountType.Trezor,
])(
  'rechecks %s durable host authority after RPC and before key/device entry',
  async (kind) => {
    let current = true;
    const persistSigned = jest.fn(async () => undefined);
    const f = fixture(kind, () => ({
      assertCurrent() {
        if (!current) throw new Error('Durable authority revoked');
      },
      persistSigned,
    }));
    f.provider.estimateGas.mockImplementationOnce(async () => {
      current = false;
      return BigNumber.from(42000);
    });
    await expect(f.submit('send', false, undefined, true)).rejects.toThrow(
      'Durable authority revoked'
    );
    expect(f.provider.estimateGas).toHaveBeenCalledTimes(1);
    expect(f.keyAccess).not.toHaveBeenCalled();
    expect(f.device).not.toHaveBeenCalled();
    expect(persistSigned).not.toHaveBeenCalled();
    expect(f.provider.sendTransaction).not.toHaveBeenCalled();
  }
);

it.each(['cancel', 'speed-up'] as const)(
  'keeps %s preview read-only without a persistence capability',
  async (operation) => {
    const capture = jest.fn(() => {
      throw Error('Preview must not capture submission');
    });
    const f = fixture(KeyringAccountType.Ledger, capture);
    await f.submit(operation, true);
    expect(capture).not.toHaveBeenCalled();
    expect(f.provider.sendTransaction).not.toHaveBeenCalled();
  }
);

it('rejects host A-B-A revision changes after persistence even when account/network values match again', async () => {
  const entered = deferred(),
    ack = deferred();
  let revision = 0;
  const f = fixture(KeyringAccountType.HDAccount, () => {
    const captured = revision;
    return {
      assertCurrent() {
        if (revision !== captured) throw Error('Host revision changed');
      },
      async persistSigned() {
        entered.resolve();
        await ack.promise;
      },
    };
  });
  const result = f.submit('send').catch((e) => e);
  await Promise.race([
    entered.promise,
    result.then((value) => {
      throw new Error(`Completed before persistence: ${JSON.stringify(value)}`);
    }),
  ]);
  revision += 2;
  ack.resolve();
  expect(await result).toMatchObject({ transactionNotBroadcast: true });
  expect(f.provider.sendTransaction).not.toHaveBeenCalled();
});

it.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
  'preserves dispatched status if the %s token post-send callback fails',
  async (kind) => {
    const f = fixture(kind, () => ({
      assertCurrent: () => undefined,
      persistSigned: async () => undefined,
    }));
    await expect(
      f.submit('erc20', false, () => {
        throw Error('history unavailable');
      })
    ).rejects.toMatchObject({
      transactionNotBroadcast: false,
      message: 'history unavailable',
    });
    expect(f.provider.sendTransaction).toHaveBeenCalledTimes(1);
  }
);

it('preserves local dispatch evidence through the formatted-send public error wrapper', async () => {
  const f = fixture(KeyringAccountType.HDAccount, () => ({
    assertCurrent: () => undefined,
    persistSigned: async () => undefined,
  }));
  f.provider.sendTransaction.mockRejectedValueOnce(
    Object.assign(Error('response lost'), { transactionNotBroadcast: true })
  );
  const error = await f.submit('send').catch((e) => e);
  expect(error).toMatchObject({ transactionNotBroadcast: false });
  expect(evmSubmissionFailure(error).transactionNotBroadcast).toBe(false);
});
