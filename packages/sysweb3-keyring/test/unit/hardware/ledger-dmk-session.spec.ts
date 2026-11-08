import { EMPTY, of, Subject } from 'rxjs';

import { LedgerDmkSession } from '../../../src/ledger/dmk-session';

const tick = async () => {
  await Promise.resolve();
  await Promise.resolve();
};
const mockDmk = (requireDeviceSelection = false) => {
  const state = new Subject<any>();
  const discovered = new Subject<any[]>();
  const dmk = {
    startDiscovering: jest.fn(() =>
      of({ id: 'selected', transport: 'WEB-HID' })
    ),
    listenToAvailableDevices: jest.fn(() => discovered),
    connect: jest.fn().mockResolvedValue('session'),
    disconnect: jest.fn().mockResolvedValue(undefined),
    getDeviceSessionState: jest.fn(() => state),
  };
  return {
    dmk,
    state,
    discovered,
    session: new LedgerDmkSession(dmk as any, requireDeviceSelection),
  };
};

const candidate = (id = 'chosen') => ({
  id,
  transport: 'RN_BLE',
  name: 'Ledger',
  deviceModel: { id, model: 'flex', name: 'Ledger Flex' },
});

describe('Ledger explicit device selection', () => {
  it('connects only the chosen handle with an immutable target and no discovery fallback', async () => {
    const { dmk, session } = mockDmk(true);
    await expect(session.connect()).rejects.toMatchObject({
      code: 'HARDWARE_SIGNER_UNAVAILABLE',
    });
    const select = session.beginDeviceSelection();
    const chosen = candidate();
    const connecting = select(chosen);
    chosen.id = 'different-device';
    chosen.transport = 'different-transport';
    await connecting;
    await expect(select(candidate('other'))).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await session.connect();
    expect(dmk.connect).toHaveBeenCalledTimes(1);
    expect(dmk.connect).toHaveBeenCalledWith({ device: candidate() });
    expect(Object.isFrozen(dmk.connect.mock.calls[0][0].device)).toBe(true);
    expect(dmk.startDiscovering).not.toHaveBeenCalled();
    expect(dmk.listenToAvailableDevices).not.toHaveBeenCalled();
    await session.disconnect();
  });

  it('rejects invalid handles and vendor reconnect handles without consuming discovery', async () => {
    const { dmk, session } = mockDmk();
    const getter = jest.fn(() => 'hidden');
    const withGetter = Object.defineProperty(candidate(), 'id', {
      get: getter,
    });
    for (const invalid of [
      { ...candidate(), id: '' },
      { ...candidate(), sessionId: undefined },
      Object.create({ sessionId: 'foreign' }),
      withGetter,
    ]) {
      const select = session.beginDeviceSelection();
      await expect(select(invalid)).rejects.toMatchObject({
        code: 'LEDGER_INVALID_DEVICE',
      });
      await expect(select(candidate())).rejects.toMatchObject({
        code: 'HARDWARE_REQUEST_CANCELLED',
      });
    }
    await expect(
      session.connect({ useGrantedDevices: true })
    ).rejects.toMatchObject({
      code: 'HARDWARE_SIGNER_UNAVAILABLE',
    });
    expect(getter).not.toHaveBeenCalled();
    expect(dmk.connect).not.toHaveBeenCalled();
    expect(dmk.startDiscovering).not.toHaveBeenCalled();
    expect(dmk.listenToAvailableDevices).not.toHaveBeenCalled();
  });

  it('retires old picker scopes across replacement, lock, and same-device selection', async () => {
    const { dmk, session } = mockDmk(true);
    const chosen = candidate();
    const first = session.beginDeviceSelection();
    const second = session.beginDeviceSelection();
    await expect(first(chosen)).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await session.disconnect();
    const fresh = session.beginDeviceSelection();
    await expect(second(chosen)).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await fresh(chosen);
    expect(dmk.connect).toHaveBeenCalledTimes(1);
    expect(() => session.beginDeviceSelection()).toThrow(
      'Ledger connection is already pending or active'
    );
    await session.disconnect();
  });

  it('does not dispatch a selected connection revoked while earlier cleanup is pending', async () => {
    const { dmk, session } = mockDmk(true);
    await session.beginDeviceSelection()(candidate('old'));
    let release!: () => void;
    dmk.disconnect.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        })
    );
    const closing = session.disconnect();
    const pending = session.beginDeviceSelection()(candidate('new'));
    await tick();
    const locked = session.disconnect();
    release();
    await expect(pending).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await Promise.all([closing, locked]);
    expect(dmk.connect).toHaveBeenCalledTimes(1);
  });

  it('closes a late DMK connection on abort before admitting another selection', async () => {
    const { dmk, session } = mockDmk(true);
    const controller = new AbortController();
    let release!: (sessionId: string) => void;
    dmk.connect.mockImplementationOnce(
      () =>
        new Promise<string>((resolve) => {
          release = resolve;
        })
    );
    const pending = session.beginDeviceSelection(controller.signal)(
      candidate()
    );
    await tick();
    controller.abort();
    expect(() => session.beginDeviceSelection()).toThrow(
      'Ledger connection is already pending or active'
    );
    release('session');
    await expect(pending).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);
    expect(dmk.disconnect).toHaveBeenCalledWith({ sessionId: 'session' });
    expect(dmk.getDeviceSessionState).not.toHaveBeenCalled();
    expect(session.getStatus()).toEqual({ connected: false });
    await session.beginDeviceSelection()(candidate());
    expect(session.getStatus()).toEqual({ connected: true });
    await session.disconnect();
  });

  it('releases the connection if its DMK state stream ends during admission', async () => {
    const { dmk, session } = mockDmk(true);
    dmk.getDeviceSessionState.mockReturnValueOnce(EMPTY as any);
    await expect(
      session.beginDeviceSelection()(candidate())
    ).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    expect(session.getStatus()).toEqual({ connected: false });
    expect(dmk.disconnect).toHaveBeenCalledWith({ sessionId: 'session' });
  });

  it('revokes a selection cancelled just before connection completion is delivered', async () => {
    const { dmk, state, session } = mockDmk(true);
    const controller = new AbortController();
    dmk.getDeviceSessionState.mockImplementationOnce(() => {
      queueMicrotask(() => controller.abort());
      return state;
    });
    await expect(
      session.beginDeviceSelection(controller.signal)(candidate())
    ).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    expect(session.getStatus()).toEqual({ connected: false });
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);
    expect(dmk.disconnect).toHaveBeenCalledWith({ sessionId: 'session' });
  });

  it('revokes late handoff cancellation after connection cleanup listeners are removed', async () => {
    const { dmk, state, session } = mockDmk(true);
    const controller = new AbortController();
    dmk.getDeviceSessionState.mockImplementationOnce(() => {
      queueMicrotask(() => queueMicrotask(() => controller.abort()));
      return state;
    });
    await expect(
      session.beginDeviceSelection(controller.signal)(candidate())
    ).rejects.toMatchObject({ code: 'HARDWARE_REQUEST_CANCELLED' });
    expect(session.getStatus()).toEqual({ connected: false });
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);
  });

  it('keeps a selected connection unavailable to device actions until picker handoff', async () => {
    const { dmk, state, session } = mockDmk(true);
    const controller = new AbortController();
    const createAction = jest.fn(() => ({
      observable: of({ status: 'completed' as const, output: 'device result' }),
      cancel: jest.fn(),
    }));
    let status: ReturnType<typeof session.getStatus> | undefined;
    let connection: Promise<unknown> | undefined;
    let operation: Promise<unknown> | undefined;
    dmk.getDeviceSessionState.mockImplementationOnce(() => {
      queueMicrotask(() => {
        status = session.getStatus();
        connection = session.connect().catch((error: unknown) => error);
        operation = session
          .runAction(createAction)
          .catch((error: unknown) => error);
        queueMicrotask(() => queueMicrotask(() => controller.abort()));
      });
      return state;
    });

    await expect(
      session.beginDeviceSelection(controller.signal)(candidate())
    ).rejects.toMatchObject({ code: 'HARDWARE_REQUEST_CANCELLED' });
    expect(createAction).not.toHaveBeenCalled();
    expect(status).toEqual({ connected: false });
    expect(await connection).toMatchObject({
      code: 'HARDWARE_SIGNER_UNAVAILABLE',
    });
    expect(await operation).toMatchObject({
      code: 'HARDWARE_SIGNER_UNAVAILABLE',
    });
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);

    await session.beginDeviceSelection()(candidate());
    await expect(session.runAction(createAction)).resolves.toBe(
      'device result'
    );
    expect(createAction).toHaveBeenCalledTimes(1);
    await session.disconnect();
  });
});

describe('Ledger DMK session ownership', () => {
  it('connects the selected device and refuses concurrent pickers', async () => {
    const { dmk, session } = mockDmk();
    const pending = new Subject<any>();
    dmk.startDiscovering.mockReturnValue(pending as any);
    const connection = session.connect();
    await expect(session.connect()).rejects.toMatchObject({
      code: 'HARDWARE_SIGNER_BUSY',
    });
    pending.next({ id: 'chosen', transport: 'WEB-HID' });
    await connection;
    expect(dmk.connect).toHaveBeenCalledWith({
      device: { id: 'chosen', transport: 'WEB-HID' },
    });
    await session.disconnect();
  });

  it('waits past the initial empty granted-device emission and rejects ambiguity', async () => {
    const { dmk, discovered, session } = mockDmk();
    const connection = session.connect({ useGrantedDevices: true });
    discovered.next([]);
    expect(dmk.connect).not.toHaveBeenCalled();
    discovered.next([{ id: 'one' }, { id: 'two' }]);
    await expect(connection).rejects.toMatchObject({
      code: 'HARDWARE_SIGNER_AMBIGUOUS',
    });
    expect(dmk.startDiscovering).not.toHaveBeenCalled();
  });

  it('serializes complete operations rather than their individual APDUs', async () => {
    const { session } = mockDmk();
    await session.connect();
    const first = new Subject<any>();
    const second = new Subject<any>();
    const createFirst = jest.fn(() => ({
      observable: first,
      cancel: jest.fn(),
    }));
    const createSecond = jest.fn(() => ({
      observable: second,
      cancel: jest.fn(),
    }));
    const p1 = session.runAction(createFirst);
    const p2 = session.runAction(createSecond);
    await tick();
    expect(createFirst).toHaveBeenCalledTimes(1);
    expect(createSecond).not.toHaveBeenCalled();
    first.next({ status: 'completed', output: 'first' });
    await expect(p1).resolves.toBe('first');
    await tick();
    expect(createSecond).toHaveBeenCalledTimes(1);
    second.next({ status: 'completed', output: 'second' });
    await expect(p2).resolves.toBe('second');
    await session.disconnect();
  });

  it('aborts active I/O, ignores late output, and revokes queued requests', async () => {
    const { session, dmk } = mockDmk();
    await session.connect();
    const result = new Subject<any>();
    const cancel = jest.fn();
    const signal = new AbortController();
    const first = session.runAction(() => ({ observable: result, cancel }), {
      signal: signal.signal,
    });
    const queuedFactory = jest.fn(() => ({
      observable: of({ status: 'completed' as const, output: 'stale' }),
      cancel: jest.fn(),
    }));
    const queued = session.runAction(queuedFactory);
    await tick();
    signal.abort();
    result.next({ status: 'completed', output: 'late signature' });
    await expect(first).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await expect(queued).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);
    expect(queuedFactory).not.toHaveBeenCalled();
  });

  it('never creates a new device action from a cancelled async continuation', async () => {
    const { session } = mockDmk();
    await session.connect();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const factory = jest.fn(() => ({
      observable: of({ status: 'completed' as const, output: 'bad' }),
      cancel: jest.fn(),
    }));
    const pending = session.runExclusive(async (operation) => {
      await gate;
      return operation.runAction(factory);
    });
    await tick();
    await session.disconnect();
    release();
    await expect(pending).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    await tick();
    expect(factory).not.toHaveBeenCalled();
  });

  it('rejects an observable that completes without a terminal result', async () => {
    const { session } = mockDmk();
    await session.connect();
    const result = new Subject<any>();
    const pending = session.runAction(() => ({
      observable: result,
      cancel: jest.fn(),
    }));
    await tick();
    result.complete();
    await expect(pending).rejects.toMatchObject({
      code: 'LEDGER_INCOMPLETE_ACTION',
    });
    await session.disconnect();
  });

  it('closes the session if a progress consumer fails, without recursive cancellation', async () => {
    const { session, dmk } = mockDmk();
    await session.connect();
    const result = new Subject<any>();
    const cancel = jest.fn(() => result.next({ status: 'stopped' }));
    const pending = session.runAction(() => ({ observable: result, cancel }), {
      onProgress: () => {
        throw new Error('closed UI');
      },
    });
    await tick();
    result.next({
      status: 'pending',
      intermediateValue: { requiredUserInteraction: 'sign-transaction' },
    });
    await expect(pending).rejects.toMatchObject({
      code: 'HARDWARE_REQUEST_CANCELLED',
    });
    expect(cancel).toHaveBeenCalledTimes(1);
    expect(dmk.disconnect).toHaveBeenCalledTimes(1);
    expect(session.getStatus().connected).toBe(false);
  });
});

describe('Ledger connection status observation', () => {
  it('reports selected handoff and physical disconnect exactly once', async () => {
    const { session, state } = mockDmk(true);
    const observed: boolean[] = [];
    const unsubscribe = session.subscribeStatus(() =>
      observed.push(session.getStatus().connected)
    );
    expect(session.getStatus().connected).toBe(false);
    await session.beginDeviceSelection()(candidate());
    expect(observed).toEqual([true]);
    state.complete();
    expect(observed).toEqual([true, false]);
    await session.disconnect();
    expect(observed).toEqual([true, false]);
    unsubscribe();
  });

  it('publishes error and explicit disconnection without observer control over cleanup', async () => {
    for (const event of ['error', 'disconnect'] as const) {
      const { session, state, dmk } = mockDmk(true);
      const observed: boolean[] = [];
      session.subscribeStatus(() => {
        throw new Error('Observer failure');
      });
      const unsubscribe = session.subscribeStatus(() =>
        observed.push(session.getStatus().connected)
      );
      await session.beginDeviceSelection()(candidate());
      if (event === 'error') state.error(new Error('Disconnected'));
      else await session.disconnect();
      await tick();
      expect(observed).toEqual([true, false]);
      expect(session.getStatus().connected).toBe(false);
      expect(dmk.disconnect).toHaveBeenCalledTimes(1);
      unsubscribe();
    }
  });

  it('unsubscribes observers and ignores an earlier connection stream after reconnect', async () => {
    const { session, state, dmk } = mockDmk(true);
    const nextState = new Subject<any>();
    const observed: boolean[] = [];
    const unsubscribe = session.subscribeStatus(() =>
      observed.push(session.getStatus().connected)
    );
    await session.beginDeviceSelection()(candidate());
    await session.disconnect();
    dmk.getDeviceSessionState.mockReturnValue(nextState);
    await session.beginDeviceSelection()(candidate('next'));
    expect(observed).toEqual([true, false, true]);
    state.complete();
    expect(session.getStatus().connected).toBe(true);
    expect(observed).toEqual([true, false, true]);
    unsubscribe();
    nextState.complete();
    expect(observed).toEqual([true, false, true]);
  });
});
