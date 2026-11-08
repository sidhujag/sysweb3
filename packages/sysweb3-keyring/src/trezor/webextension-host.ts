import { TREZOR_METHODS } from './host-types';
import { assertHardwareOperationCurrent } from '../hardware-transaction-authority';

import type { TrezorHostCalls, TrezorHost } from './host-types';
import type {
  ConnectDynamicSettings,
  TrezorConnectPublicAPI,
} from '@trezor/connect-webextension';

type Client = TrezorConnectPublicAPI<ConnectDynamicSettings>;
export type TrezorWebExtensionSettings = Parameters<Client['init']>[0];
// Connect exports one vendor client per module. Lease it to one host at a time.
const owners = new WeakMap<Client, object>();

/** Connect 10's webextension module registers Chrome listeners on import. */
const requireExtensionHost = (): void => {
  const chrome = (globalThis as any).chrome;
  if (
    !chrome?.runtime?.id ||
    chrome.runtime.getManifest?.()?.manifest_version !== 3 ||
    typeof chrome.runtime.onConnect?.addListener !== 'function' ||
    typeof chrome.runtime.onMessageExternal?.addListener !== 'function' ||
    typeof chrome.tabs?.get !== 'function' ||
    typeof chrome.tabs?.create !== 'function' ||
    typeof chrome.tabs?.update !== 'function' ||
    typeof chrome.windows?.getCurrent !== 'function'
  ) {
    throw Object.assign(
      new Error('Trezor requires a supported MV3 extension host'),
      { code: 'HARDWARE_SIGNER_UNAVAILABLE' }
    );
  }
};

/** Explicit browser composition. The shared signer never loads this module. */
export function createTrezorWebExtensionHost(
  settings: TrezorWebExtensionSettings
): TrezorHost {
  const owner = {};
  let clientPromise: Promise<Client> | undefined;
  let readyClient: Client | undefined;
  const getClient = (): Promise<Client> => {
    requireExtensionHost();
    if (!clientPromise) {
      clientPromise = import('@trezor/connect-webextension')
        .then((module) => module.default)
        .catch((error) => {
          clientPromise = undefined;
          throw error;
        });
    }
    return clientPromise;
  };
  const calls = Object.fromEntries(
    TREZOR_METHODS.map((method) => [
      method,
      (assertCurrent: () => void, ...args: any[]) => {
        const client = readyClient;
        if (!client || owners.get(client) !== owner)
          throw Object.assign(
            new Error('Trezor client is not owned by this host'),
            {
              code: 'HARDWARE_SIGNER_UNAVAILABLE',
            }
          );
        assertHardwareOperationCurrent(assertCurrent);
        return (client[method] as any)(...args);
      },
    ])
  ) as TrezorHostCalls;

  return {
    ...calls,
    async init(assertCurrent) {
      assertHardwareOperationCurrent(assertCurrent);
      readyClient = undefined;
      const client = await getClient();
      assertHardwareOperationCurrent(assertCurrent);
      const activeOwner = owners.get(client);
      if (activeOwner && activeOwner !== owner)
        throw Object.assign(
          new Error('Trezor client is owned by another host'),
          {
            code: 'HARDWARE_SIGNER_BUSY',
          }
        );
      owners.set(client, owner);
      assertHardwareOperationCurrent(assertCurrent);
      await client.init({ ...settings, env: 'webextension' });
      assertHardwareOperationCurrent(assertCurrent);
      readyClient = client;
    },
    async dispose(pendingCalls) {
      readyClient = undefined;
      const loaded = clientPromise;
      if (!loaded) return;
      // Closing Desktop's socket during a raw call opens Suite Web. Fence the
      // caller in the shared adapter while letting the raw call settle here.
      await Promise.allSettled(pendingCalls);
      const client = await loaded;
      if (owners.get(client) !== owner) return;
      // Connect 10.0.1's Desktop cancel discards an internal Promise.
      await client.dispose();
      owners.delete(client);
    },
  };
}
