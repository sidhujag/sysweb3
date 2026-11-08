import {
  ledgerCancelledError,
  ledgerHostError,
  type LedgerOperationOptions,
} from './host-types';

import type {
  DeviceManagementKit,
  DiscoveredDevice,
} from '@ledgerhq/device-management-kit';
import type { Observable, Subscription } from 'rxjs';

type Action<Output> = {
  observable: Observable<
    | { status: 'not-started' | 'stopped' }
    | {
        status: 'pending';
        intermediateValue: { requiredUserInteraction: string; step?: string };
      }
    | { status: 'completed'; output: Output }
    | { status: 'error'; error: unknown }
  >;
  cancel(): void;
};

export interface LedgerDmkOperation {
  readonly dmk: DeviceManagementKit;
  readonly sessionId: string;
  readonly generation: number;
  readonly signal: AbortSignal;
  assertCurrent(): void;
  runAction<Output>(createAction: () => Action<Output>): Promise<Output>;
}

type SelectedDevice = Readonly<{ device: DiscoveredDevice; owner: object }>;
type DmkConnection = { sessionId: string; pendingSelection?: object };

function snapshotDiscoveredDevice(candidate: object): DiscoveredDevice {
  const invalid = () =>
    ledgerHostError('LEDGER_INVALID_DEVICE', 'Invalid Ledger discovery handle');
  if (
    !candidate ||
    Object.getPrototypeOf(candidate) !== Object.prototype ||
    'sessionId' in candidate
  )
    throw invalid();
  const ownValue = (key: keyof DiscoveredDevice): unknown =>
    Object.getOwnPropertyDescriptor(candidate, key)?.value;
  const id = ownValue('id');
  const transport = ownValue('transport');
  const name = ownValue('name');
  const deviceModel = ownValue('deviceModel');
  if (
    typeof id !== 'string' ||
    !id.trim() ||
    typeof transport !== 'string' ||
    !transport.trim() ||
    typeof name !== 'string' ||
    !deviceModel ||
    typeof deviceModel !== 'object' ||
    Array.isArray(deviceModel)
  )
    throw invalid();
  // The vendor uses transport and ID to connect. Keep a stable snapshot
  // without copying extra fields, particularly the reconnect discriminator.
  return Object.freeze({
    id,
    transport,
    name,
    deviceModel: deviceModel as DiscoveredDevice['deviceModel'],
  });
}

/** One owner and one semantic operation at a time, across EVM and UTXO apps. */
export class LedgerDmkSession {
  private generation = 0;
  private connection: DmkConnection | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  private activeCancel: (() => void) | undefined;
  private activeAbort: AbortController | undefined;
  private closing: Promise<void> = Promise.resolve();
  private closingResult: Promise<void> = Promise.resolve();
  private readonly closeObservers = new Set<(result: Promise<void>) => void>();
  private stateSubscription: Subscription | undefined;
  private connectionAttempt: Promise<void> | undefined;
  private connectionAbort: AbortController | undefined;
  private deviceSelection: object | undefined;
  private readonly invalidationListeners = new Set<() => void>();
  private readonly statusListeners = new Set<() => void>();
  private reportedConnected = false;

  constructor(
    readonly dmk: DeviceManagementKit,
    private requireDeviceSelection = false
  ) {}

  private get readyConnection(): DmkConnection | undefined {
    // A provisional lease belongs to cleanup until its picker accepts handoff.
    return this.connection?.pendingSelection ? undefined : this.connection;
  }

  getStatus() {
    return { connected: this.readyConnection !== undefined };
  }

  subscribeStatus(listener: () => void): () => void {
    this.statusListeners.add(listener);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  private publishStatus(): void {
    const connected = this.getStatus().connected;
    if (connected === this.reportedConnected) return;
    this.reportedConnected = connected;
    for (const listener of this.statusListeners) {
      try {
        listener();
      } catch {
        /* Observation cannot change device ownership. */
      }
    }
  }

  onInvalidated(listener: () => void): () => void {
    this.invalidationListeners.add(listener);
    return () => this.invalidationListeners.delete(listener);
  }

  private invalidate(): void {
    this.generation++;
    this.deviceSelection = undefined;
    for (const listener of this.invalidationListeners) listener();
  }

  /** The platform passes one candidate from its own current DMK picker. */
  beginDeviceSelection(
    signal?: AbortSignal
  ): (candidate: object) => Promise<void> {
    if (signal?.aborted) throw ledgerCancelledError();
    if (this.connection || this.connectionAttempt) throw this.connectionBusy();
    this.requireDeviceSelection = true;
    const selection = {};
    this.deviceSelection = selection;
    let used = false;
    const assertCurrent = () => {
      if (this.deviceSelection !== selection || signal?.aborted)
        throw ledgerCancelledError();
    };
    return async (candidate) => {
      assertCurrent();
      if (used) throw ledgerCancelledError();
      used = true;
      try {
        const device = snapshotDiscoveredDevice(candidate);
        assertCurrent();
        await this.startConnection(
          {},
          { signal },
          { device, owner: selection }
        );
        const connection = this.connection;
        // The connection listener is gone by this handoff. A close in that
        // interval must still retire this selection's newly acquired session.
        if (connection?.pendingSelection === selection && signal?.aborted)
          await this.disconnect();
        assertCurrent();
        if (connection?.pendingSelection !== selection)
          throw ledgerCancelledError();
        connection.pendingSelection = undefined;
        this.publishStatus();
      } finally {
        if (this.deviceSelection === selection)
          this.deviceSelection = undefined;
      }
    };
  }

  /** Device selection belongs to the visible host, never to a dapp request. */
  connect(
    request: { useGrantedDevices?: boolean } = {},
    options: LedgerOperationOptions = {}
  ): Promise<void> {
    if (options.signal?.aborted) return Promise.reject(ledgerCancelledError());
    if (this.readyConnection?.sessionId) return Promise.resolve();
    if (this.requireDeviceSelection)
      return Promise.reject(
        ledgerHostError(
          'HARDWARE_SIGNER_UNAVAILABLE',
          'Select a Ledger device first'
        )
      );
    return this.startConnection(request, options);
  }

  private connectionBusy() {
    return ledgerHostError(
      'HARDWARE_SIGNER_BUSY',
      'Ledger connection is already pending or active'
    );
  }

  private startConnection(
    request: { useGrantedDevices?: boolean },
    options: LedgerOperationOptions,
    selected?: SelectedDevice
  ): Promise<void> {
    if (options.signal?.aborted) return Promise.reject(ledgerCancelledError());
    if (this.connectionAttempt) return Promise.reject(this.connectionBusy());
    const controller = new AbortController();
    this.connectionAbort = controller;
    const abort = () => controller.abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    const connecting = this.connectDevice(request, controller.signal, selected);
    const attempt = connecting.finally(async () => {
      options.signal?.removeEventListener('abort', abort);
      try {
        if (controller.signal.aborted) {
          if (this.connection) await this.disconnect();
          else await this.closing;
          throw ledgerCancelledError();
        }
      } finally {
        if (this.connectionAttempt === attempt)
          this.connectionAttempt = undefined;
        if (this.connectionAbort === controller)
          this.connectionAbort = undefined;
      }
    });
    this.connectionAttempt = attempt;
    return attempt;
  }

  private discoverDevice(
    request: { useGrantedDevices?: boolean },
    signal: AbortSignal
  ): Promise<DiscoveredDevice> {
    let subscription: Subscription | undefined;
    return new Promise<DiscoveredDevice>((resolve, reject) => {
      let settled = false;
      const timer = request.useGrantedDevices
        ? setTimeout(
            () =>
              finish(
                ledgerHostError(
                  'HARDWARE_SIGNER_UNAVAILABLE',
                  'Select a Ledger device in the Ledger window'
                )
              ),
            3000
          )
        : undefined;
      const finish = (error?: unknown, selected?: DiscoveredDevice) => {
        if (settled) return;
        settled = true;
        if (timer) clearTimeout(timer);
        subscription?.unsubscribe();
        signal.removeEventListener('abort', onAbort);
        if (error) reject(error);
        else resolve(selected!);
      };
      const onAbort = () => finish(ledgerCancelledError());
      signal.addEventListener('abort', onAbort, { once: true });
      // Calling startDiscovering synchronously preserves the click's activation.
      const discovery: Observable<DiscoveredDevice | DiscoveredDevice[]> =
        request.useGrantedDevices
          ? this.dmk.listenToAvailableDevices({})
          : this.dmk.startDiscovering({});
      subscription = discovery.subscribe({
        next: (value) => {
          const devices = Array.isArray(value) ? value : [value];
          if (!devices.length) return;
          if (devices.length !== 1) {
            finish(
              ledgerHostError(
                'HARDWARE_SIGNER_AMBIGUOUS',
                'Select one Ledger device in the Ledger window'
              )
            );
            return;
          }
          finish(undefined, devices[0]);
        },
        error: (error) => finish(error),
        complete: () => {
          if (!settled)
            finish(
              ledgerHostError(
                'HARDWARE_SIGNER_UNAVAILABLE',
                'No Ledger device selected'
              )
            );
        },
      });
      if (settled) subscription?.unsubscribe();
    });
  }

  private async connectDevice(
    request: { useGrantedDevices?: boolean },
    signal: AbortSignal,
    selected?: SelectedDevice
  ): Promise<void> {
    const generation = this.generation;
    const isCurrent = () => generation === this.generation && !signal.aborted;
    const device =
      selected?.device ?? (await this.discoverDevice(request, signal));
    if (!isCurrent()) throw ledgerCancelledError();
    await this.closing;
    if (!isCurrent()) throw ledgerCancelledError();
    const sessionId = await this.dmk.connect({ device });
    const connection = { sessionId, pendingSelection: selected?.owner };
    let subscription: Subscription | undefined;
    let ended = false;
    try {
      if (!isCurrent()) throw ledgerCancelledError();
      subscription = this.dmk.getDeviceSessionState({ sessionId }).subscribe({
        error: () => {
          ended = true;
          if (isCurrent() && this.connection === connection)
            void this.disconnect();
        },
        complete: () => {
          ended = true;
          if (isCurrent() && this.connection === connection) {
            this.connection = undefined;
            this.invalidate();
            this.activeAbort?.abort();
            this.activeCancel?.();
            this.publishStatus();
          }
        },
      });
      if (ended || !isCurrent()) throw ledgerCancelledError();
    } catch (error) {
      subscription?.unsubscribe();
      await this.closeSession(sessionId);
      throw error;
    }
    this.connection = connection;
    this.stateSubscription = subscription;
    this.publishStatus();
  }

  /** Cancel revokes the result and closes I/O; it cannot undo on-device approval. */
  disconnect(): Promise<void> {
    this.invalidate();
    this.connectionAbort?.abort();
    const sessionId = this.connection?.sessionId;
    this.connection = undefined;
    this.activeAbort?.abort();
    this.activeAbort = undefined;
    this.activeCancel?.();
    this.activeCancel = undefined;
    this.stateSubscription?.unsubscribe();
    this.stateSubscription = undefined;
    if (sessionId) this.closeSession(sessionId);
    this.publishStatus();
    return this.closing;
  }

  private closeSession(sessionId: string): Promise<void> {
    const result = this.closing.then(() => this.dmk.disconnect({ sessionId }));
    this.closingResult = result;
    this.closing = result.catch(() => undefined);
    for (const observe of this.closeObservers) observe(result);
    return this.closing;
  }

  /** Join late vendor admission and its cleanup after immediate revocation. */
  async retire(): Promise<() => void> {
    const attempt = this.connectionAttempt;
    const closes = [this.closingResult];
    const observe = (result: Promise<void>) => closes.push(result);
    this.closeObservers.add(observe);
    try {
      const disconnected = this.disconnect();
      const generation = this.generation;
      await disconnected;
      await attempt?.catch(() => undefined);
      await this.closing;
      const results = await Promise.allSettled(closes);
      const failed = results.find((result) => result.status === 'rejected');
      if (failed?.status === 'rejected') throw failed.reason;
      const assertRetired = () => {
        if (
          generation !== this.generation ||
          this.connectionAttempt ||
          this.deviceSelection ||
          this.connection
        )
          throw ledgerCancelledError();
      };
      assertRetired();
      return assertRetired;
    } finally {
      this.closeObservers.delete(observe);
    }
  }

  runExclusive<Output>(
    operation: (session: LedgerDmkOperation) => Promise<Output>,
    options: LedgerOperationOptions = {}
  ): Promise<Output> {
    const generation = this.generation;
    const admitted = this.readyConnection;
    const run = async () => {
      await this.closing;
      const connection = this.readyConnection;
      const assertCurrent = () => {
        options.assertCurrent?.();
        if (generation !== this.generation || options.signal?.aborted)
          throw ledgerCancelledError();
        if (
          !connection?.sessionId ||
          this.readyConnection !== connection ||
          (this.requireDeviceSelection && admitted !== connection)
        )
          throw ledgerHostError(
            'HARDWARE_SIGNER_UNAVAILABLE',
            'Connect a Ledger device first'
          );
      };
      assertCurrent();
      const controller = new AbortController();
      this.activeAbort = controller;
      let rejectCancellation: (error: Error) => void = () => undefined;
      const cancelled = new Promise<never>((_, reject) => {
        rejectCancellation = reject;
      });
      controller.signal.addEventListener(
        'abort',
        () => rejectCancellation(ledgerCancelledError()),
        { once: true }
      );
      const onAbort = () => {
        rejectCancellation(ledgerCancelledError());
        void this.disconnect();
      };
      options.signal?.addEventListener('abort', onAbort, { once: true });
      try {
        assertCurrent();
        const context: LedgerDmkOperation = {
          dmk: this.dmk,
          sessionId: connection!.sessionId,
          generation,
          signal: controller.signal,
          assertCurrent,
          runAction: <T>(createAction: () => Action<T>) => {
            assertCurrent();
            return this.awaitAction(createAction(), assertCurrent, options);
          },
        };
        const result = await Promise.race([operation(context), cancelled]);
        assertCurrent();
        return result;
      } finally {
        options.signal?.removeEventListener('abort', onAbort);
        if (this.activeAbort === controller) this.activeAbort = undefined;
      }
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  runAction<Output>(
    createAction: (session: LedgerDmkOperation) => Action<Output>,
    options?: LedgerOperationOptions
  ): Promise<Output> {
    return this.runExclusive(
      (session) => session.runAction(() => createAction(session)),
      options
    );
  }

  private awaitAction<Output>(
    action: Action<Output>,
    assertCurrent: () => void,
    options: LedgerOperationOptions
  ): Promise<Output> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const subscription: { current?: Subscription } = {};
      const finish = (error?: unknown, output?: Output) => {
        if (settled) return;
        settled = true;
        subscription.current?.unsubscribe();
        if (this.activeCancel === cancel) this.activeCancel = undefined;
        if (error) reject(error);
        else resolve(output as Output);
      };
      const cancel = () => {
        // cancel() may synchronously emit Stopped. Revoke this callback first
        // so that a stale-state observer cannot recursively cancel it.
        if (this.activeCancel === cancel) this.activeCancel = undefined;
        try {
          action.cancel();
        } catch {
          // The generation is already revoked; cleanup cannot revive it.
        } finally {
          finish(ledgerCancelledError());
        }
      };
      this.activeCancel = cancel;
      subscription.current = action.observable.subscribe({
        next: (state) => {
          try {
            assertCurrent();
            options.onProgress?.({
              status: state.status,
              ...(state.status === 'pending'
                ? {
                    requiredUserInteraction:
                      state.intermediateValue.requiredUserInteraction,
                    ...(typeof state.intermediateValue.step === 'string'
                      ? { step: state.intermediateValue.step }
                      : {}),
                  }
                : {}),
            });
            switch (state.status) {
              case 'completed':
                finish(undefined, state.output);
                break;
              case 'error':
                finish(
                  state.error ??
                    ledgerHostError(
                      'LEDGER_ACTION_FAILED',
                      'Ledger action failed'
                    )
                );
                break;
              case 'stopped':
                finish(ledgerCancelledError());
                break;
            }
          } catch (error) {
            // A broken progress consumer must not release our queue while the
            // device still has a signing operation in flight.
            void this.disconnect();
            finish(error);
          }
        },
        error: (error) => finish(error),
        complete: () => {
          if (!settled)
            finish(
              ledgerHostError(
                'LEDGER_INCOMPLETE_ACTION',
                'Ledger action ended without a result'
              )
            );
        },
      });
      if (settled) subscription.current.unsubscribe();
    });
  }
}
