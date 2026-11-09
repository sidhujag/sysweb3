import { execFileSync } from 'child_process';
import { Transaction } from 'ethers/transaction';
import { Wallet } from 'ethers/wallet';
import path from 'path';

import { BigNumber, serializeTransaction } from '../../../src/ethers-v6';
import { captureHardwareTransactionAuthority } from '../../../src/hardware-transaction-authority';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { TrezorKeyring } from '../../../src/trezor';
import { KeyringAccountType } from '../../../src/types';
import { withEvmSendIdentity } from '../../helpers/evm-send-identity';
import {
  admitTestSignedDispatch,
  createTestSubmissionCapture,
} from '../../helpers/evm-submission';

const specializedApproval = {
  mode: 'specialized' as const,
  assertCurrent: () => undefined,
};

const connect = jest.requireMock('../../../src/trezor/connect');
const schemaHelper = path.join(
  __dirname,
  '../../helpers/trezor-ethereum-schema.cjs'
);
const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const recipient = `0x${'22'.repeat(20)}`;

function assertPublishedConnectSchema(request: unknown): void {
  const result = JSON.parse(
    execFileSync(
      process.execPath,
      [
        schemaHelper,
        JSON.stringify(request, (_key, value) => {
          return typeof value === 'bigint'
            ? { sdkTestBigInt: value.toString() }
            : value;
        }),
      ],
      { encoding: 'utf8' }
    )
  );
  if (!result.valid)
    throw new Error('Published Connect schema rejected transaction request');
}

async function finishDeviceRequest(pending: Promise<any>): Promise<any> {
  const settled = pending.then(
    (value) => ({ value }),
    (error) => ({ error })
  );
  await jest.advanceTimersByTimeAsync(2000);
  const outcome = await settled;
  if ('error' in outcome) throw outcome.error;
  return outcome.value;
}

let sdk: EthereumTransactions;
let provider: any;
let persistSigned: jest.Mock;
let requests: any[];
beforeEach(() => {
  jest.useFakeTimers();
  requests = [];
  const state: any = {
    activeAccountType: KeyringAccountType.Trezor,
    activeAccountId: 0,
    activeNetwork: {
      kind: 'ethereum',
      chainId: 57057,
      slip44: 60,
      currency: 'eth',
      url: 'https://offline.invalid',
    },
    accounts: { Trezor: { 0: { id: 0, address: wallet.address } } },
  };
  provider = {
    verifyConfiguredChainId: jest.fn().mockResolvedValue(undefined),
    getTransactionCount: jest.fn().mockResolvedValue(7),
    getGasPrice: jest.fn().mockResolvedValue(BigNumber.from(99)),
    getFeeData: jest.fn().mockResolvedValue({
      maxFeePerGas: BigNumber.from(100),
      maxPriorityFeePerGas: BigNumber.from(2),
    }),
    estimateGas: jest.fn().mockResolvedValue(BigNumber.from(21000)),
    sendTransaction: jest.fn(async (raw: string) => ({
      hash: Transaction.from(raw).hash,
    })),
  };
  const trezor = Object.create(TrezorKeyring.prototype);
  trezor.connection = {
    // Schema assertions below still run against the published Connect package;
    // the actual owned init/drain lifecycle has separate adapter coverage.
    async withOwnedSigning(authority, operation) {
      const owner = captureHardwareTransactionAuthority(authority);
      const result = await operation(connect);
      owner.assertCurrent();
      return result;
    },
  };
  // Hardware initialization/retry are isolated; the real keyring method and
  // HD path construction still pass the exact request to the Connect boundary.
  trezor.executeWithRetry = jest.fn((operation) => operation());
  connect.ethereumSignTransaction = jest.fn(async (request) => {
    requests.push(request);
    assertPublishedConnectSchema(request);
    const tx = request.transaction;
    const signature = wallet.signingKey.sign(
      Transaction.from(
        serializeTransaction({ ...tx, type: tx.gasPrice === undefined ? 2 : 0 })
      ).unsignedHash
    );
    return {
      success: true,
      payload: { r: signature.r, s: signature.s, v: signature.v.toString(16) },
    };
  });
  connect.ethereumSignTransactionOwned = jest.fn((request, authority) => {
    authority.assertCurrent();
    return connect.ethereumSignTransaction(request);
  });
  sdk = new EthereumTransactions(
    () => state.activeNetwork,
    () => {
      throw new Error('Hardware path must not read a software key');
    },
    () => state,
    undefined,
    trezor,
    () => () => undefined,
    createTestSubmissionCapture()
  );
  jest.spyOn(sdk, 'setWeb3Provider').mockImplementation(() => {
    (sdk as any)._web3Provider = provider;
    (sdk as any)._web3ProviderKey = '57057|https://offline.invalid';
  });
  persistSigned = jest.fn(async () => undefined);
  (sdk as any).captureSubmissionLifecycle = () => ({
    assertCurrent: () => undefined,
    dispatchSigned: admitTestSignedDispatch,
    persistSigned,
  });
});
afterEach(() => {
  jest.useRealTimers();
  jest.restoreAllMocks();
});

it.each([
  ['decimal', '100', 100n],
  ['hex', '0x64', 100n],
  ['number', 100, 100n],
  ['BigNumber', BigNumber.from(100), 100n],
  ['zero', 0, 0n],
  ['hex zero', '0x0', 0n],
  ['missing', undefined, 99n],
  ['null', null, 99n],
])(
  'uses the published Connect quantity schema for legacy gas price %s',
  async (_label, gasPrice, expected) => {
    const pending = sdk.sendFormattedTransaction(
      {
        from: wallet.address,
        to: recipient,
        chainId: 57057,
        nonce: 0,
        value: 1,
        data: '0x1234',
        gasLimit: 21000,
        gasPrice,
      } as any,
      true,
      withEvmSendIdentity(sdk, specializedApproval)
    );
    await expect(finishDeviceRequest(pending)).resolves.toHaveProperty('hash');
    expect(connect.ethereumSignTransaction).toHaveBeenCalledTimes(1);
    const wire = requests[0].transaction;
    for (const field of ['value', 'gasPrice', 'gasLimit', 'nonce'])
      expect(typeof wire[field]).toBe('string');
    expect(typeof wire.chainId).toBe('number');
    expect(BigInt(wire.gasPrice)).toBe(expected);
    expect(provider.getGasPrice).toHaveBeenCalledTimes(
      gasPrice == null ? 1 : 0
    );
    expect(persistSigned).toHaveBeenCalledTimes(1);
    expect(provider.sendTransaction).toHaveBeenCalledTimes(1);
    const signed = Transaction.from(provider.sendTransaction.mock.calls[0][0]);
    expect(signed.gasPrice).toBe(expected);
    expect(signed.unsignedSerialized).toBe(
      serializeTransaction({ ...wire, type: 0 })
    );
  }
);

it('keeps every EIP1559 quantity in the published Connect schema after request capture', async () => {
  const pending = sdk.sendFormattedTransaction(
    {
      from: wallet.address,
      to: recipient,
      chainId: 57057,
      nonce: 0,
      value: 1,
      data: '0x1234',
      gasLimit: 21000,
      maxFeePerGas: 100,
      maxPriorityFeePerGas: 2,
      accessList: [
        { address: recipient, storageKeys: [`0x${'33'.repeat(32)}`] },
      ],
    } as any,
    false,
    withEvmSendIdentity(sdk, specializedApproval)
  );
  await expect(finishDeviceRequest(pending)).resolves.toHaveProperty('hash');
  const wire = requests[0].transaction;
  for (const field of [
    'value',
    'gasLimit',
    'nonce',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
  ])
    expect(typeof wire[field]).toBe('string');
  expect(typeof wire.chainId).toBe('number');
  expect(wire.gasPrice).toBeUndefined();
  const signed = Transaction.from(provider.sendTransaction.mock.calls[0][0]);
  expect(signed.unsignedSerialized).toBe(
    serializeTransaction({ ...wire, type: 2 })
  );
  expect(persistSigned).toHaveBeenCalledTimes(1);
});

it('formats autofilled EIP1559 fees, gas and nonce for the real Connect schema', async () => {
  const pending = sdk.sendFormattedTransaction(
    {
      from: wallet.address,
      to: recipient,
      chainId: 57057,
      value: 0,
      data: '0x',
    } as any,
    false,
    withEvmSendIdentity(sdk, specializedApproval)
  );
  await expect(finishDeviceRequest(pending)).resolves.toHaveProperty('hash');
  const wire = requests[0].transaction;
  for (const field of [
    'value',
    'gasLimit',
    'nonce',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
  ])
    expect(typeof wire[field]).toBe('string');
  expect(typeof wire.chainId).toBe('number');
  expect(provider.estimateGas).toHaveBeenCalledTimes(1);
  expect(provider.getFeeData).toHaveBeenCalledTimes(1);
  expect(provider.getTransactionCount).toHaveBeenCalledTimes(1);
  expect(provider.getGasPrice).not.toHaveBeenCalled();
  expect(
    Transaction.from(provider.sendTransaction.mock.calls[0][0])
      .unsignedSerialized
  ).toBe(serializeTransaction({ ...wire, type: 2 }));
});
