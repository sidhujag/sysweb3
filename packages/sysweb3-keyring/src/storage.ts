import { sysweb3Di } from '@sidhujag/sysweb3-core';
import CryptoJS from 'crypto-js';

const storage = sysweb3Di.getStateStorageDb();

// Simple async mutex implementation to prevent concurrent vault operations
class AsyncMutex {
  private mutex = Promise.resolve();

  async runExclusive<T>(callback: () => Promise<T>): Promise<T> {
    const oldMutex = this.mutex;

    let release: () => void;
    this.mutex = new Promise((resolve) => {
      release = resolve;
    });

    await oldMutex;
    try {
      return await callback();
    } finally {
      release!();
    }
  }
}

const vaultMutex = new AsyncMutex();

// Single vault for all networks - stores the mnemonic and can derive accounts for any slip44
export const setEncryptedVault = async (decryptedVault: any, pwd: string) => {
  return vaultMutex.runExclusive(async () => {
    const encryptedVault = CryptoJS.AES.encrypt(
      JSON.stringify(decryptedVault),
      pwd
    );

    // Always use single 'vault' key for all networks
    await storage.set('vault', encryptedVault.toString());
  });
};

export const getDecryptedVault = async (pwd: string) => {
  return vaultMutex.runExclusive(async () => {
    // Always use single 'vault' key
    const vault = await storage.get('vault');

    if (!vault) {
      throw new Error('Vault not found');
    }

    const decryptedVault = CryptoJS.AES.decrypt(vault, pwd).toString(
      CryptoJS.enc.Utf8
    );

    if (!decryptedVault) {
      throw new Error(
        'Failed to decrypt vault - invalid password or corrupted data'
      );
    }

    return JSON.parse(decryptedVault);
  });
};
