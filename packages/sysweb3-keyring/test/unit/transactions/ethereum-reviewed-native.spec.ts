import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';

import { EthereumTransactions } from '../../../src/transactions/ethereum';
import * as preparedSigner from '../../../src/transactions/prepared-evm';
import { KeyringAccountType } from '../../../src/types';

const wallet = new Wallet(`0x${'19'.repeat(32)}`);
const network = {
  kind: 'ethereum',
  chainId: 743211,
  slip44: 60,
  url: 'https://rpc.invalid',
} as const;
const request = () => ({
  from: wallet.address,
  to: `0x${'22'.repeat(20)}`,
  data: '0x',
  chainId: String(network.chainId),
  nonce: '0',
  value: '1000000000000000001',
  gasLimit: '25200',
  type: 2 as const,
  maxFeePerGas: '9007199254740999',
  maxPriorityFeePerGas: '0',
});

function fixture(withPersistence = true) {
  const stages: string[] = [];
  const persistSigned = jest.fn(async () => {
    stages.push('persist');
  });
  const provider = {
    verifyConfiguredChainId: jest.fn(async () => undefined),
    sendTransaction: jest.fn(async (bytes: string) => {
      stages.push('dispatch');
      return Transaction.from(bytes);
    }),
  };
  const key = jest.fn(() => ({
    address: wallet.address,
    decryptedPrivateKey: wallet.privateKey,
  }));
  const sdk = new EthereumTransactions(
    () => network as any,
    key,
    () =>
      ({
        activeNetwork: network,
        activeAccountId: 0,
        activeAccountType: KeyringAccountType.HDAccount,
        accounts: { HDAccount: { 0: { address: wallet.address } } },
      } as any),
    undefined,
    undefined,
    () => () => undefined,
    withPersistence
      ? () => ({ assertCurrent: () => undefined, persistSigned })
      : undefined
  );
  Object.defineProperty(sdk, 'web3Provider', { get: () => provider });
  return { sdk, key, provider, stages, persistSigned };
}
const approve = {
  mode: 'reviewed-native' as const,
  assertCurrent: () => undefined,
};

it.each([
  undefined,
  { mode: 'specialized' },
  { mode: 'reviewed-native' },
  {
    mode: 'reviewed-native',
    assertCurrent: () => {
      throw new Error('Stale approval');
    },
  },
])(
  'requires current host authority before reading the chain or touching a key',
  async (options) => {
    const { sdk, key, provider } = fixture();
    await expect(
      sdk.sendFormattedTransaction(request(), false, options as any)
    ).rejects.toMatchObject({
      transactionNotBroadcast: true,
    });
    expect(provider.verifyConfiguredChainId).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
    expect(key).not.toHaveBeenCalled();
  }
);

it('rejects incomplete approved fields and a missing durable port before chain I/O', async () => {
  const withoutPort = fixture(false);
  const malformed = fixture();
  for (const [f, tx] of [
    [withoutPort, request()],
    [malformed, { ...request(), nonce: undefined }],
  ] as const) {
    await expect(
      f.sdk.sendFormattedTransaction(tx as any, false, approve)
    ).rejects.toMatchObject({
      transactionNotBroadcast: true,
    });
    expect(f.provider.verifyConfiguredChainId).not.toHaveBeenCalled();
    expect(f.key).not.toHaveBeenCalled();
    expect(f.provider.sendTransaction).not.toHaveBeenCalled();
  }
});

it('signs the captured exact reviewed bytes after durable admission, without nonce or fee autofill', async () => {
  const { sdk, provider, stages, persistSigned } = fixture();
  let resume!: () => void;
  provider.verifyConfiguredChainId.mockImplementation(
    () =>
      new Promise<void>((resolve) => {
        resume = resolve;
      })
  );
  const input = request();
  const sending = sdk.sendFormattedTransaction(input, false, approve);
  input.nonce = '12';
  input.maxFeePerGas = '999999999999999999';
  input.value = '1';
  resume();
  const response = await sending;
  expect(response).toMatchObject({
    nonce: 0,
    maxFeePerGas: BigInt(request().maxFeePerGas),
    value: BigInt(request().value),
    gasLimit: BigInt(request().gasLimit),
  });
  expect(stages).toEqual(['persist', 'dispatch']);
  expect(persistSigned).toHaveBeenCalledTimes(1);
});

it('refuses a valid signature over a different nonce before retaining or broadcasting', async () => {
  const { sdk, provider, persistSigned } = fixture();
  const sign = preparedSigner.signPreparedEvmEnvelope;
  const signer = jest
    .spyOn(preparedSigner, 'signPreparedEvmEnvelope')
    .mockImplementation((transaction, key) => ({
      ...sign(transaction, key),
      signed: sign({ ...transaction, nonce: '1' }, key).signed,
    }));
  try {
    await expect(
      sdk.sendFormattedTransaction(request(), false, approve)
    ).rejects.toMatchObject({
      message:
        'Signed EVM transaction does not match expected unsigned envelope',
      transactionNotBroadcast: true,
    });
    expect(persistSigned).not.toHaveBeenCalled();
    expect(provider.sendTransaction).not.toHaveBeenCalled();
  } finally {
    signer.mockRestore();
  }
});
