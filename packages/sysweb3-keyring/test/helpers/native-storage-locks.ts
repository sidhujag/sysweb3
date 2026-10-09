/** A shared-origin Web Locks model for storage tests, with real queued callbacks. */
export const installNativeStorageTestClient = (client: object) => {
  const originalChrome = Object.getOwnPropertyDescriptor(globalThis, 'chrome');
  const originalNavigator = Object.getOwnPropertyDescriptor(
    globalThis,
    'navigator'
  );
  const tails = new Map<string, Promise<unknown>>();
  const request = jest.fn(
    (
      name: string,
      options: { mode: string },
      callback: (lock: { mode: string; name: string }) => unknown
    ) => {
      const previous = tails.get(name) || Promise.resolve();
      const result = previous
        .catch(() => undefined)
        .then(() => callback({ name, mode: options.mode }));
      tails.set(
        name,
        result.catch(() => undefined)
      );
      return result;
    }
  );
  Object.defineProperty(globalThis, 'chrome', {
    configurable: true,
    value: { storage: { local: client } },
  });
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: { locks: { request } },
  });
  return {
    request,
    restore() {
      if (originalChrome)
        Object.defineProperty(globalThis, 'chrome', originalChrome);
      else delete (globalThis as any).chrome;
      if (originalNavigator)
        Object.defineProperty(globalThis, 'navigator', originalNavigator);
      else delete (globalThis as any).navigator;
    },
  };
};
