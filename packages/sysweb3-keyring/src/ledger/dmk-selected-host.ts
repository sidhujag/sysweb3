import { createLedgerHostForDmk, type LedgerDmkHost } from './dmk-host';
import type { LedgerEvmConfig } from './host-types';

/** A platform-owned transport and explicit user selection are required. */
export function createSelectedLedgerDmkHost(
  config: LedgerEvmConfig & { dmk: object }
): LedgerDmkHost {
  return createLedgerHostForDmk(config.dmk, config, true);
}

export type { LedgerDmkHost } from './dmk-host';
