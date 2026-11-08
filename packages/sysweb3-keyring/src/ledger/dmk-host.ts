import { createLedgerEvmAdapter } from './dmk-evm';
import { LedgerDmkSession } from './dmk-session';
import { createLedgerUtxoAdapter } from './dmk-utxo';
import {
  ledgerHostError,
  type LedgerEvmConfig,
  type LedgerHost,
} from './host-types';

import type { DeviceManagementKit } from '@ledgerhq/device-management-kit';

export interface LedgerDmkHost extends LedgerHost {
  /** Observe connection changes; read getStatus() in the callback. */
  subscribeStatus(listener: () => void): () => void;
  /** Start before enumerating. The returned capability is single use. */
  beginDeviceSelection(
    signal?: AbortSignal
  ): (candidate: object) => Promise<void>;
}

/** Shared implementation; the default browser host supplies its own transport. */
export function createLedgerHostForDmk(
  candidate: object,
  config: LedgerEvmConfig,
  requireDeviceSelection?: boolean
): LedgerDmkHost {
  for (const method of [
    'connect',
    'disconnect',
    'executeDeviceAction',
    'startDiscovering',
    'listenToAvailableDevices',
    'getDeviceSessionState',
  ]) {
    if (
      typeof (candidate as Record<string, unknown> | undefined)?.[method] !==
      'function'
    )
      throw ledgerHostError(
        'LEDGER_INVALID_HOST',
        'Invalid Ledger device manager'
      );
  }
  // Keep upstream exports-only types out of the public declaration. A trusted
  // platform supplies its DMK; dapps cannot select this object.
  const session = new LedgerDmkSession(
    candidate as DeviceManagementKit,
    requireDeviceSelection
  );
  return {
    connect: (request, options) => session.connect(request, options),
    beginDeviceSelection: (signal) => session.beginDeviceSelection(signal),
    disconnect: () => session.disconnect(),
    getStatus: () => session.getStatus(),
    subscribeStatus: (listener) => session.subscribeStatus(listener),
    evm: createLedgerEvmAdapter(session, config),
    utxo: createLedgerUtxoAdapter(session),
  };
}
