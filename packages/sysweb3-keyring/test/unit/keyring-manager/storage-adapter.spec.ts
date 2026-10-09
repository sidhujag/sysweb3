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
});
