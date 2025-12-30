import { sysweb3Di } from '@sidhujag/sysweb3-core';
import CryptoJS from 'crypto-js';

const storage = sysweb3Di.getStateStorageDb();

type VaultGcmEnvelopeV4 = {
  v: 4;
  alg: 'A256GCM';
  iv: string; // hex (12 bytes)
  ct: string; // hex (ciphertext + tag)
};

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

const isHex = (s: string): boolean => /^[0-9a-fA-F]+$/.test(s);

const hexToBytes = (hex: string): Uint8Array => {
  const clean = (hex || '').trim();
  if (!isHex(clean) || clean.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
};

const bytesToHex = (bytes: ArrayBuffer): string => {
  const u8 = new Uint8Array(bytes);
  let hex = '';
  for (let i = 0; i < u8.length; i++) {
    hex += u8[i].toString(16).padStart(2, '0');
  }
  return hex;
};

const maybeParseGcmEnvelope = (raw: any): VaultGcmEnvelopeV4 | null => {
  if (!raw || typeof raw !== 'string') return null;
  if (!raw.trim().startsWith('{')) return null;
  try {
    const parsed = JSON.parse(raw) as Partial<VaultGcmEnvelopeV4>;
    if (
      parsed &&
      parsed.v === 4 &&
      parsed.alg === 'A256GCM' &&
      typeof parsed.iv === 'string' &&
      typeof parsed.ct === 'string'
    ) {
      return parsed as VaultGcmEnvelopeV4;
    }
    return null;
  } catch {
    return null;
  }
};

const encryptVaultWebCrypto = async (
  plaintextJson: string,
  keyHex: string
): Promise<VaultGcmEnvelopeV4> => {
  const subtle = (globalThis as any).crypto.subtle as SubtleCrypto;
  const iv = new Uint8Array(12);
  (globalThis as any).crypto.getRandomValues(iv);

  const keyBytes = hexToBytes(keyHex);
  if (keyBytes.length !== 32) {
    throw new Error('Vault key must be 32 bytes (hex length 64)');
  }

  const key = await subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );

  const pt = new TextEncoder().encode(plaintextJson);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    pt as unknown as BufferSource
  );

  return {
    v: 4,
    alg: 'A256GCM',
    iv: bytesToHex(iv.buffer),
    ct: bytesToHex(ct),
  };
};

const decryptVaultWebCrypto = async (
  envelope: VaultGcmEnvelopeV4,
  keyHex: string
): Promise<string> => {
  const subtle = (globalThis as any).crypto.subtle as SubtleCrypto;
  const keyBytes = hexToBytes(keyHex);
  if (keyBytes.length !== 32) {
    throw new Error('Vault key must be 32 bytes (hex length 64)');
  }
  const key = await subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const ivBytes = hexToBytes(envelope.iv);
  const ctBytes = hexToBytes(envelope.ct);
  const pt = await subtle.decrypt(
    { name: 'AES-GCM', iv: ivBytes as unknown as BufferSource },
    key,
    ctBytes as unknown as BufferSource
  );
  return new TextDecoder().decode(pt);
};

// Single vault for all networks - stores the mnemonic and can derive accounts for any slip44
export const setEncryptedVault = async (decryptedVault: any, pwd: string) => {
  return vaultMutex.runExclusive(async () => {
    const plaintext = JSON.stringify(decryptedVault);

    // Prefer WebCrypto AES-GCM when available.
    // For v4, callers pass a PBKDF2-derived hex key (32 bytes).
    // Fallback to CryptoJS passphrase-AES if WebCrypto is unavailable.
    let toStore: string;
    const canUseWebCrypto =
      !!(globalThis as any)?.crypto?.subtle &&
      !!(globalThis as any)?.crypto?.getRandomValues;

    if (
      canUseWebCrypto &&
      typeof pwd === 'string' &&
      isHex(pwd) &&
      pwd.length === 64
    ) {
      const envelope = await encryptVaultWebCrypto(plaintext, pwd);
      toStore = JSON.stringify(envelope);
    } else {
      const encryptedVault = CryptoJS.AES.encrypt(plaintext, pwd);
      toStore = encryptedVault.toString();
    }

    // Always use single 'vault' key for all networks
    await storage.set('vault', toStore);
  });
};

export const getDecryptedVault = async (pwd: string) => {
  return vaultMutex.runExclusive(async () => {
    // Always use single 'vault' key
    const vault = await storage.get('vault');

    if (!vault) {
      throw new Error('Vault not found');
    }

    // Prefer WebCrypto AES-GCM when the stored vault is in v4 envelope format.
    const maybeEnvelope = maybeParseGcmEnvelope(vault);
    let decryptedVault: string;
    if (maybeEnvelope) {
      try {
        decryptedVault = await decryptVaultWebCrypto(maybeEnvelope, pwd);
      } catch {
        throw new Error(
          'Failed to decrypt vault - invalid password or corrupted data'
        );
      }
    } else {
      // Legacy CryptoJS passphrase-AES vault (v3 and older v4 canary).
      decryptedVault = CryptoJS.AES.decrypt(vault, pwd).toString(
        CryptoJS.enc.Utf8
      );
    }

    if (!decryptedVault) {
      throw new Error(
        'Failed to decrypt vault - invalid password or corrupted data'
      );
    }

    return JSON.parse(decryptedVault);
  });
};
