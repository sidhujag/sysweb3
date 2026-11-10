import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';
import { hashMessage, Wallet } from 'ethers';

import { HardwareWalletManager } from '../../../src/hardware-wallet-manager';
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
const typedSignature = (value = data()) =>
  wallet.signingKey.sign(
    `0x${TypedDataUtils.eip712Hash(value, SignTypedDataVersion.V4).toString(
      'hex'
    )}`
  ).serialized;
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
              signature: typedSignature(),
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
  await expect(work).resolves.toBe(typedSignature());
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
  await expect(second).resolves.toBe(typedSignature());
  old.abort();
  expect((device.dispose as jest.Mock).mock.calls.length).toBe(before);
  expect(device.ethereumSignTypedData).toHaveBeenCalledTimes(2);
  await ring.retire();
});

test.each(['success', 'error'] as const)(
  'cancelled manager initialization retires its pool entry after raw %s and permits a fresh owner',
  async (outcome) => {
    const device = host(),
      connection = createTrezorConnection(device),
      manager = new HardwareWalletManager(undefined, connection),
      old = authority(),
      held = deferred();
    (device.init as jest.Mock).mockImplementationOnce(
      async (check: () => void) => {
        await held.promise;
        if (outcome === 'error')
          throw new Error('Late old initialization error');
        check();
      }
    );
    try {
      const work = connection.withOwnedSigning(old, (session) =>
        manager.initializeTrezorOwned(session, old.assertCurrent)
      );
      const rejected = expect(work).rejects.toMatchObject({
        code: 'HARDWARE_REQUEST_CANCELLED',
      });
      await jest.advanceTimersByTimeAsync(1);
      expect(device.init).toHaveBeenCalledTimes(1);
      expect(
        manager.getStatus().find((entry) => entry.type === 'trezor')?.status
      ).toBe('connecting');
      old.abort();
      await expect(
        connection.withOwnedSigning(authority(), async () => true)
      ).rejects.toMatchObject({ code: 'HARDWARE_SIGNER_BUSY' });
      held.resolve();
      await rejected;
      expect(
        manager.getStatus().find((entry) => entry.type === 'trezor')?.status
      ).toBe('disconnected');
      const next = authority();
      await expect(
        connection.withOwnedSigning(next, (session) =>
          manager.initializeTrezorOwned(session, next.assertCurrent)
        )
      ).resolves.toBe(true);
      expect(device.init).toHaveBeenCalledTimes(2);
      old.abort();
      expect(manager.isConnected('trezor' as any)).toBe(true);
    } finally {
      held.resolve();
      await manager.destroy();
    }
  }
);

test.each([
  'Device_Disconnected',
  'Device_NotFound',
  'Desktop_ConnectionMissing',
  'Transport_Missing',
])('owned Trezor preserves the current %s failure code', async (code) => {
  const device = host(),
    connection = createTrezorConnection(device);
  (device.ethereumSignTypedData as jest.Mock).mockResolvedValueOnce({
    success: false,
    error: { code, message: 'Device transport unavailable' },
  });
  try {
    await expect(
      connection.withOwnedSigning(authority(), async (session) => {
        await session.init();
        return session.ethereumSignTypedData({} as any);
      })
    ).resolves.toMatchObject({
      success: false,
      payload: { code, error: 'Device transport unavailable' },
    });
    expect(device.ethereumSignTypedData).toHaveBeenCalledTimes(1);
    await expect(connection.getFeatures()).rejects.toMatchObject({
      code: 'Init_NotInitialized',
    });
  } finally {
    await connection.dispose();
  }
});

test.each(['dispose', 'abort'] as const)(
  'owned Trezor disconnect failure cannot survive an observer %s',
  async (action) => {
    const device = host(),
      connection = createTrezorConnection(device),
      owner = authority();
    let dispatched = false;
    const unsubscribe = connection.subscribe((event) => {
      if (event.type !== 'disconnected' || !dispatched) return;
      dispatched = false;
      if (action === 'abort') owner.abort();
      else void connection.dispose();
    });
    (device.ethereumSignTypedData as jest.Mock).mockImplementationOnce(
      async () => {
        dispatched = true;
        return {
          success: false,
          error: {
            code: 'Device_Disconnected',
            message: 'Device disconnected',
          },
        };
      }
    );
    try {
      await expect(
        connection.withOwnedSigning(owner, async (session) => {
          await session.init();
          return session.ethereumSignTypedData({} as any);
        })
      ).rejects.toMatchObject({
        code:
          action === 'abort'
            ? 'HARDWARE_REQUEST_CANCELLED'
            : 'Method_Interrupted',
      });
    } finally {
      unsubscribe();
      await connection.dispose();
    }
  }
);

test('Trezor exports no unowned message signing forwards', () => {
  const connection = createTrezorConnection(host());
  for (const method of [
    'signMessage',
    'ethereumSignMessage',
    'ethereumSignTypedData',
  ])
    expect(connection).not.toHaveProperty(method);
});

test.each(['personal', 'utxo'] as const)(
  'owned Trezor %s snapshots the original message and derivation target',
  async (kind) => {
    const device = host();
    (device.ethereumSignMessage as jest.Mock).mockResolvedValue({
      success: true,
      payload: { address: wallet.address, signature: 'ab'.repeat(65) },
    });
    const ring = new TrezorKeyring(createTrezorConnection(device));
    const input = {
      address: wallet.address,
      coin: kind === 'personal' ? 'eth' : 'sys',
      slip44: kind === 'personal' ? 60 : 57,
      index: 2,
      message: kind === 'personal' ? '0x01' : 'approved',
    };
    const work = ring.signMessage(input, authority());
    input.index = 9;
    input.coin = 'btc';
    input.slip44 = 0;
    input.message = 'changed';
    input.address = '0x' + '22'.repeat(20);
    await jest.advanceTimersByTimeAsync(4300);
    await expect(work).resolves.toMatchObject({ success: true });
    const selected =
      kind === 'personal' ? device.ethereumSignMessage : device.signMessage;
    expect(selected).toHaveBeenCalledWith(
      expect.any(Function),
      kind === 'personal'
        ? { path: "m/44'/60'/0'/0/2", message: '01', hex: true }
        : { path: "m/84'/57'/2'", coin: 'sys', message: 'approved' }
    );
    expect(
      kind === 'personal' ? device.signMessage : device.ethereumSignMessage
    ).not.toHaveBeenCalled();
    await ring.retire();
  }
);

test.each(['missing', 'asynchronous', 'revoked'] as const)(
  'Trezor rejects %s authority before initialization or message dispatch',
  async (kind) => {
    const device = host(),
      ring = new TrezorKeyring(createTrezorConnection(device));
    const owner = authority();
    const invalid =
      kind === 'missing'
        ? undefined
        : kind === 'asynchronous'
        ? { signal: owner.signal, assertCurrent: async () => undefined }
        : owner;
    if (kind === 'revoked') owner.revoke();
    for (const invoke of [
      () => Reflect.apply(ring.signTypedData, ring, [typed(), invalid]),
      () =>
        Reflect.apply(ring.signMessage, ring, [
          {
            address: wallet.address,
            coin: 'eth',
            slip44: 60,
            index: 2,
            message: '01',
          },
          invalid,
        ]),
    ])
      await expect(invoke()).rejects.toMatchObject({
        code: 'HARDWARE_REQUEST_CANCELLED',
      });
    expect(device.init).not.toHaveBeenCalled();
    expect(device.ethereumSignTypedData).not.toHaveBeenCalled();
    expect(device.ethereumSignMessage).not.toHaveBeenCalled();
    await ring.retire();
  }
);

test('Trezor personal cancellation holds the signing slot until raw settlement, including a different-family successor', async () => {
  const device = host(),
    ring = new TrezorKeyring(createTrezorConnection(device)),
    old = authority(),
    held = deferred();
  (device.ethereumSignMessage as jest.Mock).mockImplementationOnce(
    async (check: () => void) => {
      await held.promise;
      check();
      return {
        success: true,
        payload: { address: wallet.address, signature: 'ab'.repeat(65) },
      };
    }
  );
  const work = ring.signMessage(
    {
      address: wallet.address,
      coin: 'eth',
      slip44: 60,
      index: 2,
      message: '01',
    },
    old
  );
  const rejected = expect(work).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await jest.advanceTimersByTimeAsync(4300);
  expect(device.ethereumSignMessage).toHaveBeenCalledTimes(1);
  old.abort();
  let settled = false;
  void work.catch(() => {
    settled = true;
  });
  await jest.advanceTimersByTimeAsync(1);
  expect(settled).toBe(false);
  await expect(ring.signTypedData(typed(), authority())).rejects.toMatchObject({
    code: 'HARDWARE_SIGNER_BUSY',
  });
  held.resolve();
  await rejected;
  const successor = ring.signTypedData(typed(), authority());
  old.abort();
  await jest.advanceTimersByTimeAsync(2200);
  await expect(successor).resolves.toBe(typedSignature());
  expect(device.ethereumSignTypedData).toHaveBeenCalledTimes(1);
  await ring.retire();
});

test('a synchronous owner revocation during held Trezor init cannot become a retry', async () => {
  const device = host(),
    ring = new TrezorKeyring(createTrezorConnection(device)),
    owner = authority(),
    held = deferred();
  (device.init as jest.Mock).mockImplementationOnce(
    async (check: () => void) => {
      await held.promise;
      check();
    }
  );
  const work = ring.signTypedData(typed(), owner),
    rejected = expect(work).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
  await jest.advanceTimersByTimeAsync(100);
  owner.revoke();
  held.resolve();
  await jest.advanceTimersByTimeAsync(10000);
  await rejected;
  expect(device.init).toHaveBeenCalledTimes(1);
  expect(device.ethereumSignTypedData).not.toHaveBeenCalled();
  await ring.retire();
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
