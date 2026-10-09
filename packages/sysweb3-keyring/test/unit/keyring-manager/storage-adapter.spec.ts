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
});
