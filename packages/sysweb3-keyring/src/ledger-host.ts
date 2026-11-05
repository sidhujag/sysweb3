/** Heavy browser host entry. Do not import from the wallet worker or software entry. */
import { DeviceManagementKitBuilder } from '@ledgerhq/device-management-kit';
import { webHidTransportFactory } from '@ledgerhq/device-transport-kit-web-hid';

import { createLedgerHostForDmk, type LedgerDmkHost } from './ledger/dmk-host';
import type { LedgerEvmConfig } from './ledger/host-types';

export interface LedgerDmkHostConfig extends LedgerEvmConfig {
  /** Platform-owned DMK, allowing a future host to register its own transports. */
  dmk?: object;
  /** Disable automatic discovery until the platform selects a device. */
  requireDeviceSelection?: boolean;
}

export function createLedgerDmkHost(
  config: LedgerDmkHostConfig = {}
): LedgerDmkHost {
  const candidate =
    config.dmk ??
    new DeviceManagementKitBuilder()
      .addTransport(webHidTransportFactory)
      .build();
  return createLedgerHostForDmk(
    candidate,
    config,
    config.requireDeviceSelection
  );
}

export type { LedgerDmkHost } from './ledger/dmk-host';
export type {
  LedgerEvmConfig,
  LedgerBlindSigningIntent,
  LedgerHost,
  LedgerEvmHost,
  LedgerUtxoHost,
  LedgerUtxoAccount,
  LedgerPartialSignature,
  LedgerTypedData,
  LedgerOperationOptions,
  LedgerProgress,
} from './ledger/host-types';
