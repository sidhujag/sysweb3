import { Wallet, Transaction } from 'ethers';

import {
  captureEvmSubmission,
  submitSignedEvmTransaction,
  submitSignedHardwareEvmTransaction,
  evmSubmissionFailure,
  type EvmSignedSubmission,
} from '../../../src/transactions/evm-submission';
import {
  admitTestSignedDispatch,
  createTestSubmissionCapture,
} from '../../helpers/evm-submission';

const wallet = new Wallet(`0x${'11'.repeat(32)}`);
const context = () => ({
  account: { id: 3, type: 'Imported', address: wallet.address },
  network: {
    kind: 'ethereum',
    chainId: 7654321,
    slip44: 60,
    url: 'https://offline.invalid',
  },
  operation: 'send' as const,
});
const deferred = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => {
    resolve = r;
  });
  return { promise, resolve };
};

const envelope = (type = 2, creation = false) => ({
  chainId: 7654321,
  nonce: 7,
  ...(creation ? { data: '0x6000' } : { to: wallet.address }),
  gasLimit: 42000,
  value: 123,
  type,
  ...(type === 2
    ? { maxFeePerGas: 3, maxPriorityFeePerGas: 1 }
    : { gasPrice: 2 }),
  ...(type
    ? {
        accessList: [
          { address: wallet.address, storageKeys: [`0x${'22'.repeat(32)}`] },
        ],
      }
    : {}),
});
const raw = (type = 2, creation = false) =>
  wallet.signTransaction(envelope(type, creation));
const expected = (type = 2, creation = false) =>
  Transaction.from(envelope(type, creation)).unsignedSerialized;
const capture = () =>
  captureEvmSubmission(
    context(),
    () => undefined,
    createTestSubmissionCapture()
  );

it('rejects a valid signed envelope that changes the captured wallet nonce', async () => {
  const persistSigned = jest.fn(async () => undefined);
  const dispatchSigned = jest.fn(admitTestSignedDispatch);
  const boundary = captureEvmSubmission(
    { ...context(), walletNonce: { nonce: 0, source: 'automatic' } },
    () => undefined,
    () => ({ assertCurrent: () => undefined, persistSigned, dispatchSigned })
  );
  const broadcast = jest.fn(async () => undefined);
  await expect(
    submitSignedEvmTransaction(
      await raw(),
      broadcast,
      boundary,
      undefined,
      expected()
    )
  ).rejects.toMatchObject({
    message: 'Signed EVM nonce does not match wallet approval',
    transactionNotBroadcast: true,
  });
  expect(persistSigned).not.toHaveBeenCalled();
  expect(dispatchSigned).not.toHaveBeenCalled();
  expect(broadcast).not.toHaveBeenCalled();
});

it.each(['Ledger', 'Trezor'])(
  'requires the internal chain-verified dispatcher for a captured %s account',
  async (type) => {
    const persistSigned = jest.fn(async () => undefined);
    const ctx = context();
    const boundary = captureEvmSubmission(
      { ...ctx, account: { ...ctx.account, type } },
      () => undefined,
      () => ({
        assertCurrent: () => undefined,
        persistSigned,
        dispatchSigned: admitTestSignedDispatch,
      })
    );
    const signed = await raw();
    const broadcast = jest.fn(async () => undefined);
    await expect(
      submitSignedEvmTransaction(
        signed,
        broadcast,
        boundary,
        undefined,
        expected()
      )
    ).rejects.toMatchObject({
      transactionNotBroadcast: true,
      message: 'EVM submission does not match the signing mode',
    });
    await expect(
      Reflect.apply(submitSignedHardwareEvmTransaction, undefined, [
        signed,
        broadcast,
        boundary,
        undefined,
        expected(),
      ])
    ).rejects.toMatchObject({
      transactionNotBroadcast: true,
      message: 'EVM submission does not match the signing mode',
    });
    expect(persistSigned).not.toHaveBeenCalled();
    expect(broadcast).not.toHaveBeenCalled();
  }
);

it.each([0, 1, 2])(
  'persists exact type%s bytes and captured immutable context before dispatch',
  async (type) => {
    const signed = await raw(type, type === 2),
      entered = deferred(),
      ack = deferred();
    const ctx = context();
    let persisted!: EvmSignedSubmission;
    const lifecycle = {
      assertCurrent: jest.fn(),
      dispatchSigned: admitTestSignedDispatch,
      persistSigned: jest.fn(async (record: EvmSignedSubmission) => {
        persisted = record;
        entered.resolve();
        await ack.promise;
      }),
    };
    const boundary = captureEvmSubmission(
      ctx,
      () => undefined,
      () => lifecycle
    );
    const broadcast = jest.fn(async (bytes: string) => ({
      hash: Transaction.from(bytes).hash,
    }));
    const promise = submitSignedEvmTransaction(
      signed,
      ({ rawTransaction, admit }) => admit(() => broadcast(rawTransaction)),
      boundary,
      undefined,
      expected(type, type === 2)
    );
    await entered.promise;
    expect(broadcast).not.toHaveBeenCalled();
    expect(persisted.rawTransaction).toBe(signed);
    expect(persisted.hash).toBe(Transaction.from(signed).hash);
    expect(Object.isFrozen(persisted)).toBe(true);
    expect(Object.isFrozen(persisted.context.account)).toBe(true);
    ctx.network.url = 'https://changed.invalid';
    lifecycle.persistSigned = jest.fn();
    ack.resolve();
    await promise;
    expect(broadcast).toHaveBeenCalledTimes(1);
    expect(broadcast).toHaveBeenCalledWith(signed);
    expect(persisted.context.network.url).toBe('https://offline.invalid');
  }
);

it.each(['reject', 'lock', 'host-revision', 'before-broadcast'])(
  'does not dispatch after %s failure and preserves saved bytes',
  async (failure) => {
    const signed = await raw(),
      ack = deferred(),
      entered = deferred();
    let current = true,
      revision = 0;
    let saved = '';
    const boundary = captureEvmSubmission(
      context(),
      () => {
        if (!current) throw Error('locked');
      },
      () => ({
        assertCurrent() {
          if (revision) throw Error('revoked');
        },
        dispatchSigned: admitTestSignedDispatch,
        async persistSigned(record) {
          saved = record.rawTransaction;
          entered.resolve();
          await ack.promise;
          if (failure === 'reject') throw Error('write acknowledgement lost');
        },
      })
    );
    const broadcast = jest.fn(),
      promise = submitSignedEvmTransaction(
        signed,
        ({ rawTransaction, admit }) => admit(() => broadcast(rawTransaction)),
        boundary,
        () => {
          if (failure === 'before-broadcast') throw Error('expired');
        },
        expected()
      );
    const outcome = promise.catch((error) => error);
    await entered.promise;
    if (failure === 'lock') current = false;
    if (failure === 'host-revision') revision++;
    ack.resolve();
    const error = await outcome;
    expect(error).toBeInstanceOf(Error);
    expect(evmSubmissionFailure(error)).toMatchObject({
      transactionNotBroadcast: true,
    });
    expect(saved).toBe(signed);
    expect(broadcast).not.toHaveBeenCalled();
  }
);

it('derives uncertainty only from its local transport invocation, never from provider fields', async () => {
  const signed = await raw();
  for (const dispatch of [false, true]) {
    const boundary = captureEvmSubmission(
      context(),
      () => undefined,
      () => ({
        assertCurrent() {
          return undefined;
        },
        dispatchSigned: admitTestSignedDispatch,
        async persistSigned() {
          if (!dispatch)
            throw Object.assign(Error('write'), {
              transactionNotBroadcast: false,
            });
        },
      })
    );
    const error = await submitSignedEvmTransaction(
      signed,
      ({ admit }) =>
        admit(async () => {
          throw Object.assign(Error('response lost'), {
            transactionNotBroadcast: true,
          });
        }),
      boundary,
      undefined,
      expected()
    ).catch((e) => e);
    expect(evmSubmissionFailure(error)).toMatchObject({
      transactionNotBroadcast: !dispatch,
    });
  }
  expect(evmSubmissionFailure({ transactionNotBroadcast: false })).toEqual({
    transactionNotBroadcast: true,
  });
});

it('refuses mismatched signed account/chain before persistence and dispatch', async () => {
  const signed = await raw(),
    persistSigned = jest.fn(async () => undefined),
    broadcast = jest.fn();
  for (const field of ['account', 'chain']) {
    const ctx = context();
    if (field === 'chain') ctx.network.chainId = 1;
    else ctx.account.address = `0x${'22'.repeat(20)}`;
    const boundary = captureEvmSubmission(
      ctx,
      () => undefined,
      () => ({
        assertCurrent() {
          return undefined;
        },
        dispatchSigned: admitTestSignedDispatch,
        persistSigned,
      })
    );
    await expect(
      submitSignedEvmTransaction(
        signed,
        broadcast,
        boundary,
        undefined,
        expected()
      )
    ).rejects.toThrow('does not match');
  }
  expect(persistSigned).not.toHaveBeenCalled();
  expect(broadcast).not.toHaveBeenCalled();
});

it('rejects async capture/guards rather than silently accepting deferred admission', () => {
  expect(() =>
    captureEvmSubmission(
      context(),
      (async () => undefined) as any,
      createTestSubmissionCapture()
    )
  ).toThrow('synchronously');
  expect(() =>
    captureEvmSubmission(
      context(),
      () => undefined,
      (async () => undefined) as any
    )
  ).toThrow('synchronously');
});

it('preserves provider error class and diagnostic fields while owning submission stage', async () => {
  class RpcError extends Error {
    code = -32000;
    data = '0x1234';
    shortMessage = 'execution reverted';
    reason = 'balance';
    info = { error: { code: 3 } };
  }
  const signed = await raw(),
    providerError = new RpcError('rpc failed');
  Object.assign(providerError, { transactionNotBroadcast: true });
  const boundary = capture();
  const error = await submitSignedEvmTransaction(
    signed,
    ({ admit }) =>
      admit(async () => {
        throw providerError;
      }),
    boundary,
    undefined,
    expected()
  ).catch((e) => e);
  expect(error).toBe(providerError);
  expect(error).toBeInstanceOf(RpcError);
  expect(error).toMatchObject({
    code: -32000,
    data: '0x1234',
    shortMessage: 'execution reverted',
    reason: 'balance',
    info: { error: { code: 3 } },
    transactionNotBroadcast: false,
  });
  expect(evmSubmissionFailure(error).transactionNotBroadcast).toBe(false);
});

it('preserves frozen provider diagnostics without accepting its forged dispatch stage', async () => {
  const providerError = Object.freeze(
    Object.assign(Error('frozen'), {
      code: -32000,
      data: '0x1234',
      shortMessage: 'revert',
      reason: 'balance',
      transactionNotBroadcast: true,
    })
  );
  const error = await submitSignedEvmTransaction(
    await raw(),
    ({ admit }) =>
      admit(async () => {
        throw providerError;
      }),
    capture(),
    undefined,
    expected()
  ).catch((e) => e);
  expect(error).toMatchObject({
    code: -32000,
    data: '0x1234',
    shortMessage: 'revert',
    reason: 'balance',
    transactionNotBroadcast: false,
  });
  expect(error.cause).toBe(providerError);
  expect(evmSubmissionFailure(error).transactionNotBroadcast).toBe(false);
});

it('rejects an omitted lifecycle, forged boundary, or missing expected envelope', async () => {
  expect(() =>
    captureEvmSubmission(context(), () => undefined, undefined as never)
  ).toThrow('durable EVM submission lifecycle is required');
  const persistSigned = jest.fn(async () => undefined);
  expect(() =>
    captureEvmSubmission(context(), () => undefined, (() => ({
      assertCurrent: () => undefined,
      persistSigned,
    })) as never)
  ).toThrow('EVM submission lifecycle must be captured synchronously');
  const lifecycle = () => ({
    assertCurrent: () => undefined,
    persistSigned,
    dispatchSigned: admitTestSignedDispatch,
  });
  const boundary = captureEvmSubmission(context(), () => undefined, lifecycle);
  const broadcast = jest.fn();
  const bytes = await raw();
  for (const [candidate, approved] of [
    [undefined, expected()],
    [{ ...boundary }, expected()],
    [boundary, undefined],
  ]) {
    await expect(
      submitSignedEvmTransaction(
        bytes,
        broadcast,
        candidate as never,
        undefined,
        approved as never
      )
    ).rejects.toMatchObject({ transactionNotBroadcast: true });
  }
  expect(persistSigned).not.toHaveBeenCalled();
  expect(broadcast).not.toHaveBeenCalled();
});

it('requires dispatch admission after transport preflight and retires late initiators', async () => {
  const bytes = await raw();
  const entered = deferred();
  const resume = deferred();
  const wire = jest.fn(async () => 'hash');
  let revoked = false;
  let late: (() => Promise<string>) | undefined;
  const boundary = captureEvmSubmission(
    context(),
    () => undefined,
    () => ({
      assertCurrent: () => undefined,
      persistSigned: async () => undefined,
      async dispatchSigned(_record, initiate) {
        if (revoked) throw new Error('durable Cancel');
        return initiate();
      },
    })
  );
  const work = submitSignedEvmTransaction(
    bytes,
    async ({ admit }) => {
      late = () => admit(wire);
      entered.resolve();
      await resume.promise;
      return late();
    },
    boundary,
    undefined,
    expected()
  );
  await entered.promise;
  revoked = true;
  resume.resolve();
  await expect(work).rejects.toMatchObject({
    transactionNotBroadcast: true,
    message: 'durable Cancel',
  });
  expect(() => late?.()).toThrow('Invalid EVM dispatch admission');
  expect(wire).not.toHaveBeenCalled();
});

it('refuses a lifecycle that invokes the wire without running its owned preflight', async () => {
  const wire = jest.fn(async () => 'hash');
  const boundary = captureEvmSubmission(
    context(),
    () => undefined,
    () => ({
      assertCurrent: () => undefined,
      persistSigned: async () => undefined,
      dispatchSigned: (_record, initiate) => initiate(),
    })
  );
  await expect(
    submitSignedEvmTransaction(
      await raw(),
      ({ admit }) => admit(wire),
      boundary,
      undefined,
      expected()
    )
  ).rejects.toMatchObject({
    transactionNotBroadcast: true,
    message: 'EVM dispatch preflight was not completed',
  });
  expect(wire).not.toHaveBeenCalled();
});

it('refuses a fire-and-forget persistence callback without dispatch', async () => {
  const boundary = captureEvmSubmission(
    context(),
    () => undefined,
    () => ({
      assertCurrent: () => undefined,
      dispatchSigned: admitTestSignedDispatch,
      persistSigned: (() => undefined) as any,
    })
  );
  const broadcast = jest.fn();
  await expect(
    submitSignedEvmTransaction(
      await raw(),
      broadcast,
      boundary,
      undefined,
      expected()
    )
  ).rejects.toMatchObject({
    transactionNotBroadcast: true,
    message: expect.stringContaining('acknowledgement Promise'),
  });
  expect(broadcast).not.toHaveBeenCalled();
});

it('preserves plain JSON-RPC error fields without accepting its dispatch claim', async () => {
  const error = await submitSignedEvmTransaction(
    await raw(),
    ({ admit }) =>
      admit(async () => {
        throw {
          message: 'rpc rejection',
          code: -32000,
          data: '0xbeef',
          transactionNotBroadcast: true,
        };
      }),
    capture(),
    undefined,
    expected()
  ).catch((e) => e);
  expect(error).toMatchObject({
    message: 'rpc rejection',
    code: -32000,
    data: '0xbeef',
    transactionNotBroadcast: false,
  });
  expect(evmSubmissionFailure(error).transactionNotBroadcast).toBe(false);
});

it('does not retain a forged signed hash when rejection precedes signed-byte validation', async () => {
  let current = true;
  const boundary = captureEvmSubmission(
    context(),
    () => {
      if (!current)
        throw Object.assign(Error('expired'), {
          signedTransactionHash: '0xforged',
          transactionNotBroadcast: false,
        });
    },
    createTestSubmissionCapture()
  );
  current = false;
  const error = await submitSignedEvmTransaction(
    await raw(),
    jest.fn(),
    boundary,
    undefined,
    expected()
  ).catch((e) => e);
  expect(error.transactionNotBroadcast).toBe(true);
  expect(error.signedTransactionHash).toBeUndefined();
});
