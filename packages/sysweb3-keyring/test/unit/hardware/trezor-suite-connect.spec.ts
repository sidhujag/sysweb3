import TrezorConnect from '@trezor/connect-webextension';
import { webcrypto } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { createContext, runInContext } from 'vm';

import { HardwareWalletManager } from '../../../src/hardware-wallet-manager';
import { TrezorKeyring } from '../../../src/trezor';

// Resolve the installed bundle by package path, bypassing Jest's Connect mock.
// Browser APIs and device responses are simulated: these tests prove SDK routing
// and message handling, not pairing or signing on a physical Safe 7.
const bundle = readFileSync(
  join(
    __dirname,
    '../../../node_modules/@trezor/connect-webextension/build/trezor-connect-webextension.js'
  ),
  'utf8'
);

const createConnectRuntime = ({
  desktopAvailable = true,
  response = { success: true, payload: { model: 'T3W1' } },
}: {
  desktopAvailable?: boolean;
  response?: any;
} = {}) => {
  const webSockets: string[] = [];
  const desktopMessages: any[] = [];
  const popupUrls: string[] = [];
  const popupMessages: any[] = [];
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const intervals = new Set<ReturnType<typeof setInterval>>();
  const connectListeners: ((port: any) => void)[] = [];
  const schedule = (callback: () => void, delay: number) => {
    const timer = setTimeout(() => {
      timers.delete(timer);
      callback();
    }, delay);
    timers.add(timer);
    return timer;
  };
  const cancelTimer = (timer: ReturnType<typeof setTimeout>) => {
    timers.delete(timer);
    clearTimeout(timer);
  };

  class SimulatedWebSocket {
    readyState = 0;
    onopen?: () => void;
    onclose?: () => void;
    onerror?: () => void;
    onmessage?: (message: { data: string }) => void;

    constructor(url: string) {
      webSockets.push(url);
      schedule(() => {
        this.readyState = desktopAvailable ? 1 : 3;
        if (desktopAvailable) this.onopen?.();
        else this.onerror?.();
      }, 0);
    }

    send(raw: string) {
      const message = JSON.parse(raw);
      desktopMessages.push(message);
      const reply =
        message.type === 'popup-handshake'
          ? { id: message.id, type: message.type, payload: 'ok' }
          : { id: message.id, ...response };
      schedule(() => this.onmessage?.({ data: JSON.stringify(reply) }), 0);
    }

    close() {
      this.readyState = 3;
      this.onclose?.();
    }
  }

  const channel = {
    here: '@trezor/connect-content-script',
    peer: '@trezor/connect-webextension',
  };
  const connectPopup = (tabId: number) => {
    const listeners: ((message: any, port: any) => void)[] = [];
    const port: any = {
      name: 'trezor-connect',
      sender: { origin: 'https://connect.trezor.io', tab: { id: tabId } },
      onMessage: { addListener: (listener: any) => listeners.push(listener) },
      disconnect: jest.fn(),
    };
    const receive = (message: any) => {
      schedule(() => {
        listeners.forEach((listener) =>
          listener({ channel, ...message }, port)
        );
      }, 0);
    };
    port.postMessage = (message: any) => {
      popupMessages.push(message);
      if (message.type === 'channel-handshake-request') {
        receive({ type: 'channel-handshake-confirm' });
      } else if (message.type === 'popup-init') {
        receive({ type: 'popup-core-loaded' });
      } else if (message.type === 'iframe-call') {
        receive({ id: message.id, type: 'response', ...response });
      }
    };
    connectListeners.forEach((listener) => listener(port));
    receive({ type: 'channel-handshake-confirm' });
    receive({ type: 'popup-loaded' });
  };
  const chrome = {
    runtime: {
      id: 'test-extension-id',
      getURL: (path: string) => `chrome-extension://test-extension-id/${path}`,
      // eslint-disable-next-line camelcase
      getManifest: () => ({ manifest_version: 3 }),
      onConnect: {
        addListener: (listener: any) => connectListeners.push(listener),
      },
      onMessage: { addListener: jest.fn() },
    },
    windows: { getCurrent: (callback: any) => callback({ type: 'normal' }) },
    permissions: {
      getAll: (callback: any) => callback({ permissions: ['scripting'] }),
    },
    scripting: { executeScript: jest.fn().mockResolvedValue([]) },
    tabs: {
      query: (_query: any, callback: any) => callback([{ id: 1, index: 0 }]),
      create: (options: any, callback: any) => {
        popupUrls.push(options.url);
        callback({ id: 2, index: 1, url: options.url });
        schedule(() => connectPopup(2), 0);
      },
      get: (id: number, callback: any) => callback({ id }),
      update: jest.fn(),
      remove: (_id: number, callback: any) => callback(),
    },
  };
  const permissionQuery = jest.fn().mockResolvedValue({ state: 'granted' });
  const context: any = {
    console,
    setTimeout: schedule,
    clearTimeout: cancelTimer,
    setInterval: (callback: () => void, delay: number) => {
      const interval = setInterval(callback, delay);
      intervals.add(interval);
      return interval;
    },
    clearInterval: (interval: ReturnType<typeof setInterval>) => {
      intervals.delete(interval);
      clearInterval(interval);
    },
    URL,
    URLSearchParams,
    AbortController,
    TextEncoder,
    TextDecoder,
    Uint8Array,
    Uint32Array,
    ArrayBuffer,
    Buffer,
    crypto: webcrypto,
    WebSocket: SimulatedWebSocket,
    navigator: { permissions: { query: permissionQuery } },
    chrome,
    location: { origin: 'chrome-extension://test-extension-id' },
  };
  context.self = context;
  createContext(context);
  runInContext(bundle, context);

  return {
    connect: context.TrezorConnect,
    webSockets,
    desktopMessages,
    popupUrls,
    popupMessages,
    permissionQuery,
    close: async () => {
      await context.TrezorConnect.dispose();
      timers.forEach(clearTimeout);
      intervals.forEach(clearInterval);
    },
  };
};

describe('Trezor Suite connection routing with the installed SDK', () => {
  let manager: HardwareWalletManager;
  let runtime: ReturnType<typeof createConnectRuntime> | undefined;
  let keyring: TrezorKeyring | undefined;

  beforeEach(() => {
    jest.clearAllMocks();
    manager = new HardwareWalletManager();
  });

  afterEach(async () => {
    await keyring?.destroy();
    keyring = undefined;
    await runtime?.close();
    runtime = undefined;
    await manager.destroy();
    jest.restoreAllMocks();
  });

  const initializeRuntime = async (runtimeOptions = {}) => {
    expect(await manager.initializeTrezor()).toBe(true);
    const options = (TrezorConnect.init as jest.Mock).mock.calls[0][0];
    runtime = createConnectRuntime(runtimeOptions);
    await runtime.connect.init(options);
    return { runtime, options };
  };

  it('routes a simulated Safe 7 response through Suite desktop without a popup', async () => {
    const { runtime } = await initializeRuntime();
    expect(runtime.webSockets).toEqual([]);

    const response = await runtime.connect.getFeatures();

    expect(response).toMatchObject({
      success: true,
      payload: { model: 'T3W1' },
    });
    expect(runtime.webSockets).toEqual(['ws://127.0.0.1:21335/connect-ws']);
    expect(runtime.permissionQuery).toHaveBeenCalledWith({
      name: 'local-network-access',
    });
    expect(runtime.desktopMessages.map((message) => message.type)).toEqual([
      'popup-handshake',
      'iframe-call',
    ]);
    expect(runtime.desktopMessages[0].payload.settings.manifest).toEqual({
      appName: 'Pali Wallet',
      appUrl: 'https://paliwallet.com/',
      email: 'support@syscoin.org',
    });
    expect(runtime.desktopMessages[1].payload.method).toBe('getFeatures');
    expect(runtime.popupUrls).toEqual([]);
  });

  it('retains the fixed legacy popup route for older devices without Suite desktop', async () => {
    const { runtime } = await initializeRuntime({
      desktopAvailable: false,
      response: { success: true, payload: { model: 'T' } },
    });

    expect(await runtime.connect.getFeatures()).toMatchObject({
      success: true,
      payload: { model: 'T' },
    });
    expect(runtime.webSockets).toEqual(['ws://127.0.0.1:21335/connect-ws']);
    expect(runtime.popupUrls).toHaveLength(1);
    const popup = new URL(runtime.popupUrls[0]);
    expect(`${popup.origin}${popup.pathname}`).toBe(
      'https://connect.trezor.io/9/popup.html'
    );
    expect(popup.searchParams.get('env')).toBe('webextension');
    expect(runtime.popupMessages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: 'iframe-call',
          payload: expect.objectContaining({ method: 'getFeatures' }),
        }),
      ])
    );
  });

  it('demonstrates that missing appName prevents the desktop branch from being used', async () => {
    const { runtime, options } = await initializeRuntime({
      response: { success: true, payload: { model: 'T' } },
    });
    await runtime.connect.dispose();
    const manifest = { ...options.manifest };
    delete manifest.appName;
    await runtime.connect.init({ ...options, manifest });

    expect(await runtime.connect.getFeatures()).toMatchObject({
      success: true,
      payload: { model: 'T' },
    });
    expect(runtime.webSockets).toEqual([]);
    expect(runtime.desktopMessages).toEqual([]);
    expect(new URL(runtime.popupUrls[0]).origin).toBe(
      'https://connect.trezor.io'
    );
  });

  it.each([
    ['Method_Cancel', 'Canceled'],
    ['Method_Interrupted', 'Popup closed'],
  ])(
    'treats the SDK %s response as terminal without another approval request',
    async (code, error) => {
      const { runtime } = await initializeRuntime({
        response: { success: false, payload: { code, error } },
      });
      jest
        .spyOn(TrezorConnect, 'getAccountInfo')
        .mockImplementation((params: any) =>
          runtime.connect.getAccountInfo(params)
        );
      keyring = new TrezorKeyring();

      await expect(
        keyring.getAccountInfo({ coin: 'sys', slip44: 57 })
      ).rejects.toThrow(error);

      expect(
        runtime.desktopMessages.filter(
          (message) => message.type === 'iframe-call'
        )
      ).toHaveLength(1);
      expect(runtime.popupUrls).toEqual([]);
    }
  );
});
