import { SignTypedDataVersion } from '@metamask/eth-sig-util';
import { hashMessage, Wallet } from 'ethers';

import { LedgerKeyring } from '../../../src/ledger';
import { EthereumTransactions } from '../../../src/transactions/ethereum';
import { TrezorKeyring } from '../../../src/trezor';
import { createTrezorConnection } from '../../../src/trezor/connect';
import {
  TREZOR_METHODS,
  type TrezorHost,
} from '../../../src/trezor/host-types';
import { KeyringAccountType } from '../../../src/types';

import type { LedgerHost } from '../../../src/ledger/host-types';

jest.unmock('../../../src/trezor/connect');

const wallet = new Wallet('0x' + '11'.repeat(32));
const data = () => ({
  domain: {},
  types: { EIP712Domain: [], Note: [{ name: 'text', type: 'string' }] },
  primaryType: 'Note',
  message: { text: 'approved' },
});
const typed = () => ({
  index: 2,
  accountIndex: 2,
  address: wallet.address,
  expectedAddress: wallet.address,
  version: SignTypedDataVersion.V4,
  data: data(),
});
const deferred = () => {
  let resolve!: (value?: any) => void;
  const promise = new Promise<any>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
const authority = () => {
  let current = true;
  const controller = new AbortController();
  return {
    signal: controller.signal,
    assertCurrent() {
      if (!current) throw new Error('Owner changed');
    },
    revoke() {
      current = false;
    },
    abort() {
      current = false;
      controller.abort();
    },
  };
};
const host = (): TrezorHost =>
  ({
    ...Object.fromEntries(
      TREZOR_METHODS.map((method) => [
        method,
        jest.fn(async (check: () => void) => {
          check();
          return {
            success: true,
            payload: {
              address: wallet.address,
              signature: '0x' + 'ab'.repeat(65),
            },
          };
        }),
      ])
    ),
    init: jest.fn(async (check: () => void) => check()),
    dispose: jest.fn(async (calls) => {
      await Promise.allSettled(calls);
    }),
  } as TrezorHost);

beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());

test('owned Trezor typed requests preserve the explicit target and immutable data', async () => {
  const device = host(),
    connection = createTrezorConnection(device),
    ring = new TrezorKeyring(connection);
  const input = typed(),
    owner = authority();
  const work = ring.signTypedData(input, owner);
  input.index = 9;
  input.data.message.text = 'changed';
  await jest.advanceTimersByTimeAsync(2200);
  await expect(work).resolves.toBe('0x' + 'ab'.repeat(65));
  expect(device.ethereumSignTypedData).toHaveBeenCalledWith(
    expect.any(Function),
    expect.objectContaining({
      path: "m/44'/60'/0'/0/2",
      data: expect.objectContaining({ message: { text: 'approved' } }),
    })
  );
  await ring.retire();
});

test.each(['startup', 'initialization', 'delay', 'retry'] as const)(
  'Trezor refuses revoked authority during %s before another device call',
  async (stage) => {
    const device = host(),
      connection = createTrezorConnection(device),
      ring = new TrezorKeyring(connection),
      owner = authority();
    const held = deferred();
    if (stage === 'initialization')
      (device.init as jest.Mock).mockImplementationOnce(
        async (check: () => void) => {
          await held.promise;
          check();
        }
      );
    if (stage === 'retry')
      (device.ethereumSignTypedData as jest.Mock).mockRejectedValueOnce(
        new Error('Transient transport failure')
      );
    const work = ring.signTypedData(typed(), owner),
      rejected = expect(work).rejects.toMatchObject({
        code: 'HARDWARE_REQUEST_CANCELLED',
      });
    if (stage !== 'startup')
      await jest.advanceTimersByTimeAsync(
        stage === 'retry' ? 2200 : stage === 'delay' ? 200 : 100
      );
    owner.abort();
    held.resolve();
    await jest.advanceTimersByTimeAsync(10000);
    await rejected;
    expect(device.ethereumSignTypedData).toHaveBeenCalledTimes(
      stage === 'retry' ? 1 : 0
    );
    await ring.retire();
  }
);

test('owned Trezor raw-call cancellation drains before a successor and cannot retire it later', async () => {
  const device = host(),
    connection = createTrezorConnection(device),
    ring = new TrezorKeyring(connection),
    old = authority(),
    held = deferred();
  (device.ethereumSignTypedData as jest.Mock).mockImplementationOnce(
    async (check: () => void) => {
      await held.promise;
      check();
      return { success: true, payload: {} };
    }
  );
  const first = ring.signTypedData(typed(), old),
    rejected = expect(first).rejects.toThrow();
  await jest.advanceTimersByTimeAsync(2200);
  old.abort();
  let settled = false;
  void first.catch(() => {
    settled = true;
  });
  await jest.advanceTimersByTimeAsync(1);
  expect(settled).toBe(false);
  await expect(ring.signTypedData(typed(), authority())).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  held.resolve();
  await rejected;
  const before = (device.dispose as jest.Mock).mock.calls.length;
  const second = ring.signTypedData(typed(), authority());
  await jest.advanceTimersByTimeAsync(2200);
  await expect(second).resolves.toBe('0x' + 'ab'.repeat(65));
  old.abort();
  expect((device.dispose as jest.Mock).mock.calls.length).toBe(before);
  expect(device.ethereumSignTypedData).toHaveBeenCalledTimes(2);
  await ring.retire();
});

test('Trezor exports no unowned message signing forwards', () => {
  const connection = createTrezorConnection(host());
  for (const method of [
    'signMessage',
    'ethereumSignMessage',
    'ethereumSignTypedData',
  ])
    expect(connection).not.toHaveProperty(method);
});

test.each(['personal', 'typed', 'utxo'] as const)(
  'Ledger %s refuses owner loss during connection before signing',
  async (kind) => {
    const held = deferred(),
      owner = authority(),
      signature = wallet.signingKey.sign(
        hashMessage(Uint8Array.of(1))
      ).serialized;
    const device: LedgerHost = {
      connect: jest.fn(async (_request, options) => {
        await held.promise;
        options!.assertCurrent!();
      }),
      disconnect: jest.fn(async () => undefined),
      retire: jest.fn(async () => () => undefined),
      getStatus: () => ({ connected: false }),
      evm: {
        signPersonalMessage: jest.fn(async () => signature),
        signTypedData: jest.fn(async () => signature),
      } as any,
      utxo: { signMessage: jest.fn(async () => signature) } as any,
    };
    const ring = new LedgerKeyring(undefined, device);
    const work =
      kind === 'typed'
        ? ring.evm.signTypedData(typed(), owner)
        : kind === 'personal'
        ? ring.evm.signPersonalMessage(
            { accountIndex: 2, expectedAddress: wallet.address, message: '01' },
            owner
          )
        : ring.signUtxoMessage(
            {
              currency: 'sys',
              slip44: 57,
              accountIndex: 2,
              accountXpub: 'public fixture',
              message: 'approved',
            },
            owner
          );
    const rejected = expect(work).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    owner.abort();
    held.resolve();
    await rejected;
    expect(device.evm.signPersonalMessage).not.toHaveBeenCalled();
    expect(device.evm.signTypedData).not.toHaveBeenCalled();
    expect(device.utxo.signMessage).not.toHaveBeenCalled();
    await ring.retire();
  }
);

test.each([KeyringAccountType.Ledger, KeyringAccountType.Trezor])(
  'raw hardware ethSign rejects %s before private-key access or device use',
  async (type) => {
    const owner = authority();
    const privateRead = jest.fn(() => {
        throw new Error('Unexpected private-key read');
      }),
      call = jest.fn();
    const network = {
      kind: 'ethereum',
      chainId: 1,
      slip44: 60,
      url: 'https://offline.invalid',
    };
    const state = {
      activeAccountId: 2,
      activeAccountType: type,
      activeNetwork: network,
      accounts: { [type]: { 2: { address: wallet.address } } },
    };
    const transactions = new EthereumTransactions(
      () => network as any,
      privateRead,
      () => state as any,
      { evm: { signPersonalMessage: call } } as any,
      { signMessage: call } as any,
      () => () => undefined,
      null
    );
    await expect(
      transactions.ethSign([wallet.address, '0x' + '22'.repeat(32)], {
        selectedAccount: { id: 2, type, expectedAddress: wallet.address },
        targetAccount: { id: 2, type, expectedAddress: wallet.address },
        signal: owner.signal,
        assertCurrent: owner.assertCurrent,
      })
    ).rejects.toMatchObject({ code: 'HARDWARE_RAW_DIGEST_UNSUPPORTED' });
    expect(privateRead).not.toHaveBeenCalled();
    expect(call).not.toHaveBeenCalled();
  }
);
