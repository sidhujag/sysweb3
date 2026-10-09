import { parseJsonRecursively } from './utils';

interface IStateStorageClient {
  getItem(key: string): string | null;
  removeItem(key: string): void | Promise<void>;
  setItem(key: string, value: string): void | Promise<void>;
  // Optional all-or-nothing batch for clients without a native set(items).
  setItems?(items: Record<string, string>): void | Promise<void>;
}

export interface IKeyValueDb {
  deleteItem(key: string): void | Promise<void>;
  get(key: string): any;
  set(key: string, value: any): void | Promise<void>;
  setMany(items: Record<string, any>): void | Promise<void>;
  setClient(client?: IStateStorageClient): void;
  setPrefix(prefix: string): void;
}

declare let window: any;
const defaultStorage =
  typeof window !== 'undefined' ? window.localStorage : undefined;

const StateStorageDb = (
  storageClient: any | undefined = defaultStorage
): IKeyValueDb => {
  let keyPrefix = 'sysweb3-';

  const setClient = (client?: IStateStorageClient) => {
    storageClient = client || defaultStorage;
  };

  const setPrefix = (prefix: string) => {
    if (!prefix) {
      prefix = 'sysweb3-';
    } else if (prefix.charAt(prefix.length - 1) !== '-') {
      prefix += '-';
    }
    keyPrefix = prefix;
  };

  const set = (key: string, value: any) => {
    if (!storageClient) return;

    if ('set' in storageClient) {
      return storageClient.set({ [keyPrefix + key]: value });
    }

    return storageClient.setItem(keyPrefix + key, JSON.stringify(value));
  };

  const setMany = (items: Record<string, any>) => {
    // Never emulate an atomic write with a sequence of setItem calls.
    // Chrome storage and the built-in memory client can commit the whole batch.
    if (storageClient && typeof storageClient.set === 'function') {
      const prefixed = Object.fromEntries(
        Object.entries(items).map(([key, value]) => [keyPrefix + key, value])
      );
      return storageClient.set(prefixed);
    }
    if (storageClient && typeof storageClient.setItems === 'function') {
      const serialized = Object.fromEntries(
        Object.entries(items).map(([key, value]) => [
          keyPrefix + key,
          JSON.stringify(value),
        ])
      );
      return storageClient.setItems(serialized);
    }
    throw new Error('Storage adapter does not support atomic batch writes');
  };

  const get = async (key: string): Promise<any> => {
    if (!storageClient) return;

    if ('get' in storageClient) {
      const value = await storageClient.get([keyPrefix + key]);
      if (value) {
        const result = parseJsonRecursively(value);
        return result[keyPrefix + key];
      }
      return {};
    }

    const value = storageClient.getItem(keyPrefix + key);
    if (value) {
      return JSON.parse(value);
    }
  };

  const deleteItem = (key: string) => {
    if (!storageClient) return;
    if ('remove' in storageClient) {
      return storageClient.remove(keyPrefix + key);
    }

    return storageClient.removeItem(keyPrefix + key);
  };

  return {
    setClient,
    setPrefix,
    set,
    setMany,
    get,
    deleteItem,
  };
};

const MemoryStorageClient = (): IStateStorageClient => {
  const memory: any = {};

  const setItem = (key: string, value: any) => {
    memory[key] = value;
  };

  const setItems = (items: Record<string, string>) => {
    Object.assign(memory, items);
  };

  const getItem = (key: string): any => memory[key];

  const removeItem = (key: string) => {
    memory[key] = null;
  };

  return {
    setItem,
    setItems,
    getItem,
    removeItem,
  };
};

const CrossPlatformDi = () => {
  //======================
  //= State Storage =
  //======================
  const stateStorageDb: IKeyValueDb = StateStorageDb(MemoryStorageClient());

  const getStateStorageDb = (): IKeyValueDb => stateStorageDb;

  return {
    getStateStorageDb,
  };
};

const SysWeb3Di = () => {
  const crossPlatformDi = CrossPlatformDi();
  const getStateStorageDb = (): IKeyValueDb =>
    crossPlatformDi.getStateStorageDb();

  return {
    getStateStorageDb,
  };
};

export const sysweb3Di = SysWeb3Di();
