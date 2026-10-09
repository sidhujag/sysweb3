import { installNativeStorageTestClient } from '../../helpers/native-storage-locks';

import type { IKeyValueDb } from '../../../../sysweb3-core/src';

const { sysweb3Di } = jest.requireActual('@sidhujag/sysweb3-core');

const deferred = () => {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
};

describe('real core asynchronous storage adapter', () => {
  const db: IKeyValueDb = sysweb3Di.getStateStorageDb();

  afterEach(() => db.setClient());

  it.each(['set', 'remove'])(
    'preserves Chrome %s completion and rejection',
    async (method) => {
      const write = deferred();
      const client = { [method]: jest.fn(() => write.promise) };
      db.setClient(client as any);
      const result =
        method === 'set'
          ? db.set('vault', 'ciphertext')
          : db.deleteItem('vault');
      expect(result).toBe(write.promise);
      let settled = false;
      const observed = Promise.resolve(result).finally(() => {
        settled = true;
      });
      await Promise.resolve();
      expect(settled).toBe(false);
      const error = new Error('Chrome storage rejected');
      write.reject(error);
      await expect(observed).rejects.toBe(error);
      expect(client[method]).toHaveBeenCalledWith(
        method === 'set' ? { 'sysweb3-vault': 'ciphertext' } : 'sysweb3-vault'
      );
    }
  );

  it.each(['setItem', 'removeItem'])(
    'preserves asynchronous %s adapters',
    async (method) => {
      const write = deferred();
      const client = { [method]: jest.fn(() => write.promise) };
      db.setClient(client as any);
      const result =
        method === 'setItem'
          ? db.set('vault', 'ciphertext')
          : db.deleteItem('vault');
      expect(result).toBe(write.promise);
      write.resolve();
      await expect(result).resolves.toBeUndefined();
    }
  );

  it('keeps synchronous localStorage clients synchronous', () => {
    const client = {
      setItem: jest.fn(),
      removeItem: jest.fn(),
      getItem: jest.fn(),
    };
    db.setClient(client);
    expect(db.set('vault', { value: 1 })).toBeUndefined();
    expect(client.setItem).toHaveBeenCalledWith('sysweb3-vault', '{"value":1}');
    expect(db.deleteItem('vault')).toBeUndefined();
    expect(client.removeItem).toHaveBeenCalledWith('sysweb3-vault');
  });

  it('commits a prefixed batch through one native call and awaits rejection', async () => {
    const write = deferred();
    const client = { set: jest.fn(() => write.promise) };
    db.setClient(client as any);
    db.setPrefix('test');
    try {
      const result = db.setMany({
        vault: 'ciphertext',
        'vault-keys': { salt: 'salt' },
      });
      expect(result).toBe(write.promise);
      expect(client.set).toHaveBeenCalledTimes(1);
      expect(client.set).toHaveBeenCalledWith({
        'test-vault': 'ciphertext',
        'test-vault-keys': { salt: 'salt' },
      });
      const error = new Error('atomic write rejected');
      write.reject(error);
      await expect(result).rejects.toBe(error);
    } finally {
      db.setPrefix('');
    }
  });

  it('rejects a sequential-only adapter before writing any batch item', () => {
    const client = {
      setItem: jest.fn(),
      getItem: jest.fn(),
      removeItem: jest.fn(),
    };
    db.setClient(client);
    expect(() =>
      db.setMany({ vault: 'ciphertext', 'vault-keys': { salt: 'salt' } })
    ).toThrow('Storage adapter does not support atomic batch writes');
    expect(client.setItem).not.toHaveBeenCalled();
  });

  it('supports an atomic batch in the built-in memory client', async () => {
    const { sysweb3Di: memoryDi } = jest.requireActual(
      '@sidhujag/sysweb3-core'
    );
    jest.resetModules();
    const { sysweb3Di: freshDi } = jest.requireActual('@sidhujag/sysweb3-core');
    const memoryDb = freshDi.getStateStorageDb();
    expect(freshDi).not.toBe(memoryDi);
    expect(
      memoryDb.setMany({ vault: 'ciphertext', 'vault-keys': { salt: 'salt' } })
    ).toBeUndefined();
    await expect(memoryDb.get('vault')).resolves.toBe('ciphertext');
    await expect(memoryDb.get('vault-keys')).resolves.toEqual({ salt: 'salt' });
  });

  describe('conditional creation across independent clients', () => {
    let nativeStorage:
      | ReturnType<typeof installNativeStorageTestClient>
      | undefined;

    const independentDb = (): IKeyValueDb => {
      let result!: IKeyValueDb;
      jest.isolateModules(() => {
        result = jest
          .requireActual('@sidhujag/sysweb3-core')
          .sysweb3Di.getStateStorageDb();
      });
      return result;
    };

    afterEach(() => {
      db.setPrefix('');
      nativeStorage?.restore();
      nativeStorage = undefined;
    });

    it('serializes separate module instances through the same native Web Lock', async () => {
      const records: Record<string, unknown> = {};
      const entered = deferred();
      const release = deferred();
      const client = {
        get: jest.fn(async (keys: string[]) =>
          Object.fromEntries(keys.map((key) => [key, records[key]]))
        ),
        set: jest.fn(async (items: Record<string, unknown>) => {
          entered.resolve();
          await release.promise;
          Object.assign(records, items);
        }),
      };
      nativeStorage = installNativeStorageTestClient(client);
      const first = independentDb();
      const second = independentDb();
      first.setClient(client as any);
      second.setClient(client as any);
      const initial = first.createManyIfAbsent({
        vault: 'first ciphertext',
        'vault-keys': { salt: 'first salt' },
      });
      await entered.promise;
      const competing = second.createManyIfAbsent({
        vault: 'second ciphertext',
        'vault-keys': { salt: 'second salt' },
      });
      await Promise.resolve();
      expect(client.get).toHaveBeenCalledTimes(1);
      expect(client.set).toHaveBeenCalledTimes(1);
      expect(records).toEqual({});
      release.resolve();
      await expect(initial).resolves.toBe(true);
      await expect(competing).resolves.toBe(false);
      expect(records).toEqual({
        'sysweb3-vault': 'first ciphertext',
        'sysweb3-vault-keys': { salt: 'first salt' },
      });
      expect(nativeStorage.request).toHaveBeenNthCalledWith(
        1,
        'sysweb3:create:sysweb3-',
        { mode: 'exclusive' },
        expect.any(Function)
      );
      expect(nativeStorage.request).toHaveBeenCalledTimes(2);
    });

    it.each([false, true])(
      'releases the lock after a failed write (already committed: %p)',
      async (commit) => {
        const records: Record<string, unknown> = {};
        const client = {
          get: jest.fn(async (keys: string[]) =>
            Object.fromEntries(keys.map((key) => [key, records[key]]))
          ),
          set: jest.fn(async (items: Record<string, unknown>) => {
            Object.assign(records, items);
          }),
        };
        nativeStorage = installNativeStorageTestClient(client);
        db.setClient(client as any);
        client.set.mockImplementationOnce(async (items) => {
          if (commit) Object.assign(records, items);
          throw new Error('lost write acknowledgement');
        });
        await expect(
          db.createManyIfAbsent({ vault: 'first', 'vault-keys': { salt: 'a' } })
        ).rejects.toThrow('lost write acknowledgement');
        await expect(
          db.createManyIfAbsent({
            vault: 'second',
            'vault-keys': { salt: 'b' },
          })
        ).resolves.toBe(!commit);
        expect(records['sysweb3-vault']).toBe(commit ? 'first' : 'second');
      }
    );

    it.each(['', false, 0, 'ciphertext'])(
      'preserves an existing native record %p without writing',
      async (value) => {
        const client = {
          get: jest.fn(async () => ({ 'sysweb3-vault': value })),
          set: jest.fn(),
        };
        nativeStorage = installNativeStorageTestClient(client);
        db.setClient(client as any);
        await expect(
          db.createManyIfAbsent({ vault: 'new', 'vault-keys': { salt: 'new' } })
        ).resolves.toBe(false);
        expect(client.set).not.toHaveBeenCalled();
      }
    );

    it('fails closed when a native client has no Web Locks support', async () => {
      const client = { get: jest.fn(), set: jest.fn() };
      nativeStorage = installNativeStorageTestClient(client);
      Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: {},
      });
      db.setClient(client as any);
      await expect(db.createManyIfAbsent({ vault: 'new' })).rejects.toThrow();
      expect(client.get).not.toHaveBeenCalled();
      expect(client.set).not.toHaveBeenCalled();
    });

    it('does not assume an arbitrary get/set backend shares this origin lock', async () => {
      nativeStorage = installNativeStorageTestClient({});
      const remote = { get: jest.fn(), set: jest.fn() };
      db.setClient(remote as any);
      await expect(db.createManyIfAbsent({ vault: 'new' })).rejects.toThrow();
      expect(remote.get).not.toHaveBeenCalled();
      expect(remote.set).not.toHaveBeenCalled();
    });

    it('uses the captured prefix and client if configuration changes while queued', async () => {
      const held = deferred();
      const release = deferred();
      const records: Record<string, unknown> = {};
      const client = {
        get: jest.fn(async (keys: string[]) =>
          Object.fromEntries(keys.map((key) => [key, records[key]]))
        ),
        set: jest.fn(async (items: Record<string, unknown>) => {
          Object.assign(records, items);
        }),
      };
      nativeStorage = installNativeStorageTestClient(client);
      const blocker = nativeStorage.request(
        'sysweb3:create:queued-',
        { mode: 'exclusive' },
        async () => {
          held.resolve();
          await release.promise;
        }
      );
      await held.promise;
      db.setPrefix('queued');
      db.setClient(client as any);
      const creation = db.createManyIfAbsent({ vault: 'queued ciphertext' });
      db.setPrefix('other');
      db.setClient({ get: jest.fn(), set: jest.fn() } as any);
      release.resolve();
      await blocker;
      await expect(creation).resolves.toBe(true);
      expect(records).toEqual({ 'queued-vault': 'queued ciphertext' });
    });

    it('supports an explicit atomic custom adapter with serialized values', async () => {
      const records: Record<string, string> = {};
      const client = {
        getItem: jest.fn((key: string) => records[key]),
        setItem: jest.fn(),
        removeItem: jest.fn(),
        createItemsIfAbsent: jest.fn((items: Record<string, string>) => {
          if (Object.keys(items).some((key) => records[key] != null))
            return false;
          Object.assign(records, items);
          return true;
        }),
      };
      db.setClient(client);
      await expect(
        db.createManyIfAbsent({
          vault: 'ciphertext',
          'vault-keys': { salt: 'a' },
        })
      ).resolves.toBe(true);
      expect(client.createItemsIfAbsent).toHaveBeenCalledWith({
        'sysweb3-vault': '"ciphertext"',
        'sysweb3-vault-keys': '{"salt":"a"}',
      });
      await expect(db.get('vault-keys')).resolves.toEqual({ salt: 'a' });
      await expect(
        db.createManyIfAbsent({ vault: 'replacement' })
      ).resolves.toBe(false);
      expect(client.setItem).not.toHaveBeenCalled();
    });

    it('keeps the memory client absence check and assignment indivisible', async () => {
      const memory = independentDb();
      const results = await Promise.all([
        memory.createManyIfAbsent({
          vault: 'first',
          'vault-keys': { salt: 'a' },
        }),
        memory.createManyIfAbsent({
          vault: 'second',
          'vault-keys': { salt: 'b' },
        }),
      ]);
      expect(results).toEqual([true, false]);
      await expect(memory.get('vault')).resolves.toBe('first');
      await expect(memory.get('vault-keys')).resolves.toEqual({ salt: 'a' });
    });
  });
});
