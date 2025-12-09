import ecc from '@bitcoinerlab/secp256k1';
import { isHexString } from '@ethersproject/bytes';
import { HDNode } from '@ethersproject/hdnode';
import { Wallet } from '@ethersproject/wallet';
import * as sysweb3 from '@sidhujag/sysweb3-core';
import {
  INetwork,
  INetworkType,
  getNetworkConfig,
} from '@sidhujag/sysweb3-network';
import { BIP32Factory } from 'bip32';
import { Psbt } from 'bitcoinjs-lib';
import bs58check from 'bs58check';
import crypto from 'crypto';
import CryptoJS from 'crypto-js';
import mapValues from 'lodash/mapValues';
import omit from 'lodash/omit';
import * as syscoinjs from 'syscoinjs-lib';
import * as BIP84 from 'syscoinjs-lib/bip84-replacement';

// Reference embedded bitcoinjs from syscoinjs-lib
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const bjs: any = (syscoinjs.utils as any).bitcoinjs;

import {
  initialActiveImportedAccountState,
  initialActiveLedgerAccountState,
  initialActiveTrezorAccountState,
} from './initial-state';
import { LedgerKeyring } from './ledger';
import { getSyscoinSigners, SyscoinHDSigner } from './signers';
import { getDecryptedVault, setEncryptedVault } from './storage';
import { EthereumTransactions, SyscoinTransactions } from './transactions';
import { TrezorKeyring } from './trezor';
import { HardwareWalletManagerSingleton } from './hardware-wallet-manager-singleton';
import { HardwareWalletManager } from './hardware-wallet-manager';
import {
  IKeyringAccountState,
  ISyscoinTransactions,
  KeyringAccountType,
  IEthereumTransactions,
  IKeyringManager,
} from './types';
import {
  getAddressDerivationPath,
  isEvmCoin,
  convertExtendedKeyVersion,
} from './utils/derivation-paths';

export interface ISysAccount {
  address: string;
  label?: string;
  xprv?: string;
  xpub: string;
}

// Dynamic ETH HD path generation - will be computed as needed

/**
 * Secure Buffer implementation for sensitive data
 * Provides explicit memory clearing capability
 */
class SecureBuffer {
  private buffer: Buffer | null;
  private _isCleared = false;

  constructor(data: string | Buffer) {
    if (typeof data === 'string') {
      this.buffer = Buffer.from(data, 'utf8');
    } else {
      this.buffer = Buffer.from(data);
    }
  }

  get(): Buffer {
    if (this._isCleared || !this.buffer) {
      throw new Error('SecureBuffer has been cleared');
    }
    return Buffer.from(this.buffer); // Return copy
  }

  toString(): string {
    if (this._isCleared || !this.buffer) {
      throw new Error('SecureBuffer has been cleared');
    }
    return this.buffer.toString('utf8');
  }

  clear(): void {
    if (!this._isCleared && this.buffer) {
      // Overwrite with random data first
      crypto.randomFillSync(this.buffer);
      // Then fill with zeros
      this.buffer.fill(0);
      this.buffer = null;
      this._isCleared = true;
    }
  }

  isCleared(): boolean {
    return this._isCleared;
  }
}

export class KeyringManager implements IKeyringManager {
  public trezorSigner: TrezorKeyring;
  public ledgerSigner: LedgerKeyring;
  // NOTE: activeChain removed - now derived from vault.activeNetwork.kind
  public initialTrezorAccountState: IKeyringAccountState;
  public initialLedgerAccountState: IKeyringAccountState;
  public utf8Error: boolean;
  //transactions objects
  public ethereumTransaction: IEthereumTransactions;
  public syscoinTransaction: ISyscoinTransactions;
  private storage: any; // Should be IKeyValueDb but import issue - provides deleteItem(), get(), set(), setClient(), setPrefix()

  // Store getter function for accessing Redux state
  private getVaultState: (() => any) | null = null;

  // Method to inject store getter from Pali side
  public setVaultStateGetter = (getter: () => any) => {
    this.getVaultState = getter;
  };

  // Helper method to get current vault state
  private getVault = () => {
    if (!this.getVaultState) {
      throw new Error(
        'Vault state getter not configured. Call setVaultStateGetter() first.',
      );
    }

    const vault = this.getVaultState();

    // DEFENSIVE CHECK: Ensure vault state is properly structured
    if (!vault) {
      throw new Error(
        'Vault state is undefined. Ensure Redux store is properly initialized with vault state.',
      );
    }

    if (!vault.activeNetwork) {
      throw new Error(
        'Vault state is missing activeNetwork. Ensure vault state is properly initialized before keyring operations.',
      );
    }

    if (!vault.activeAccount) {
      throw new Error(
        'Vault state is missing activeAccount. Ensure vault state is properly initialized before keyring operations.',
      );
    }

    return vault;
  };

  // Helper to get active chain from vault state (replaces this.activeChain)
  private getActiveChain = (): INetworkType => {
    return this.getVault().activeNetwork.kind;
  };

  // Secure session data - using Buffers that can be explicitly cleared
  private sessionPassword: SecureBuffer | null = null;
  private sessionMnemonic: SecureBuffer | null = null; // can be a mnemonic or a zprv, can be changed to a zprv when using an imported wallet

  // Legacy session password for migration support - holds the old hash-based key
  // during migration from vault format v1 to v2. Cleared after migration completes.
  private legacySessionPassword: SecureBuffer | null = null;

  /**
   * @param sharedHardwareWalletManager Optional shared HardwareWalletManager instance.
   *                                     If not provided, the singleton instance will be used.
   *                                     This allows multiple KeyringManagers to share the same
   *                                     hardware wallet connections, preventing "device already open" errors.
   */
  constructor(sharedHardwareWalletManager?: HardwareWalletManager) {
    this.storage = sysweb3.sysweb3Di.getStateStorageDb();
    // Don't initialize secure buffers in constructor - they're created on unlock
    this.storage.set('utf8Error', {
      hasUtf8Error: false,
    });

    // NOTE: activeChain is now derived from vault state, not stored locally
    // NOTE: No more persistent signers - use getSigner() for fresh on-demand signers

    this.utf8Error = false;
    // sessionMnemonic is initialized as null - created on unlock
    this.initialTrezorAccountState = initialActiveTrezorAccountState;
    this.initialLedgerAccountState = initialActiveLedgerAccountState;

    // Use provided shared manager or get singleton instance
    const hardwareManager = sharedHardwareWalletManager || HardwareWalletManagerSingleton.getInstance();

    this.trezorSigner = new TrezorKeyring();
    this.ledgerSigner = new LedgerKeyring(hardwareManager);

    // this.syscoinTransaction = SyscoinTransactions();
    this.syscoinTransaction = new SyscoinTransactions(
      this.getSigner,
      this.getReadOnlySigner,
      this.getAccountsState,
      this.getAddress,
      this.ledgerSigner,
      this.trezorSigner,
    );
    this.ethereumTransaction = new EthereumTransactions(
      this.getNetwork,
      this.getDecryptedPrivateKey,
      this.getAccountsState,
      this.ledgerSigner,
      this.trezorSigner,
    );
  }

  // Static factory method for creating a fully initialized KeyringManager with slip44 support
  public static async createInitialized(
    seed: string,
    password: string,
    vaultStateGetter: () => any,
  ): Promise<KeyringManager> {
    const keyringManager = new KeyringManager();

    // Set the vault state getter
    keyringManager.setVaultStateGetter(vaultStateGetter);

    // Use the new secure initialization method (eliminates temporary plaintext storage)
    await keyringManager.initializeWalletSecurely(seed, password);

    // NOTE: Active account management is now handled by vault state/Redux
    // No need to explicitly set active account - it's managed externally

    return keyringManager;
  }

  // Convenience method for complete setup after construction
  public async initialize(
    seed: string,
    password: string,
    network?: INetwork,
  ): Promise<IKeyringAccountState> {
    // Set the network if provided (this is crucial for proper address derivation)
    if (network) {
      await this.setSignerNetwork(network);
    }

    // Use the new secure initialization method (eliminates temporary plaintext storage)
    const account = await this.initializeWalletSecurely(seed, password);

    // NOTE: Active account management is now handled by vault state/Redux
    // No need to explicitly set active account - it's managed externally

    return account;
  }

  // ===================================== PUBLIC METHODS - KEYRING MANAGER FOR HD - SYS ALL ===================================== //

  public setStorage = (client: any) => this.storage.setClient(client);

  public validateAccountType = (account: IKeyringAccountState) => {
    return account.isImported === true
      ? KeyringAccountType.Imported
      : KeyringAccountType.HDAccount;
  };

  public isUnlocked = () =>
    !!this.sessionPassword && !this.sessionPassword.isCleared();

  public lockWallet = async () => {
    // Clear secure session data
    if (this.sessionPassword) {
      this.sessionPassword.clear();
      this.sessionPassword = null;
    }
    if (this.sessionMnemonic) {
      this.sessionMnemonic.clear();
      this.sessionMnemonic = null;
    }
    // Clear legacy session password if present (migration cleanup)
    if (this.legacySessionPassword) {
      this.legacySessionPassword.clear();
      this.legacySessionPassword = null;
    }

    // Clear transaction handlers that may hold HD signers
    if (this.syscoinTransaction) {
      // Replace with empty object to clear references
      this.syscoinTransaction = {} as ISyscoinTransactions;
    }
    // NOTE: We intentionally don't clear ethereumTransaction here because
    // polling needs the web3Provider even when the wallet is locked.

    // Clean up hardware wallet connections (await to ensure HID is released)
    if (this.ledgerSigner) {
      try {
        await this.ledgerSigner.destroy();
      } catch (_) {
        // ignore
      }
    }
    if (this.trezorSigner) {
      try {
        await this.trezorSigner.destroy();
      } catch (_) {
        // ignore
      }
    }
  };

  // Direct secure transfer of session data to another keyring
  public transferSessionTo = (targetKeyring: IKeyringManager): void => {
    if (!this.isUnlocked()) {
      throw new Error('Source keyring must be unlocked to transfer session');
    }

    // Cast to access the receiveSessionOwnership method
    const targetKeyringImpl = targetKeyring as unknown as KeyringManager;

    // Transfer ownership of our buffers to the target
    if (!this.sessionPassword || !this.sessionMnemonic) {
      throw new Error('Session data is missing during transfer');
    }

    targetKeyringImpl.receiveSessionOwnership(
      this.sessionPassword,
      this.sessionMnemonic,
    );

    // Null out our references (do NOT clear buffers - target owns them now)
    this.sessionPassword = null;
    this.sessionMnemonic = null;
  };

  // Private method for zero-copy transfer - takes ownership of buffers
  public receiveSessionOwnership = (
    sessionPassword: SecureBuffer,
    sessionMnemonic: SecureBuffer,
  ): void => {
    // Clear any existing data first
    if (this.sessionPassword) {
      this.sessionPassword.clear();
    }
    if (this.sessionMnemonic) {
      this.sessionMnemonic.clear();
    }

    // Take ownership of the actual SecureBuffer objects
    // No copying - these are the original objects
    this.sessionPassword = sessionPassword;
    this.sessionMnemonic = sessionMnemonic;
  };

  public addNewAccount = async (
    label?: string,
  ): Promise<IKeyringAccountState> => {
    // Check if wallet is unlocked
    if (!this.isUnlocked()) {
      throw new Error('Wallet must be unlocked to add new accounts');
    }

    // addNewAccount should only create accounts from the main seed
    // For importing accounts (including zprvs), use importAccount
    if (this.getActiveChain() === INetworkType.Syscoin) {
      return await this.addNewAccountToSyscoinChain(label);
    } else {
      // EVM chainType
      return await this.addNewAccountToEth(label);
    }
  };

  public async unlock(password: string): Promise<{
    canLogin: boolean;
    needsAccountCreation?: boolean;
    needsXprvMigration?: boolean;
  }> {
    try {
      const vaultKeys = await this.storage.get('vault-keys');

      if (!vaultKeys) {
        return {
          canLogin: false,
        };
      }

      const { hash, salt } = vaultKeys;
      let passwordValid = false;

      // FIRST: Validate password against stored hash based on vault version
      if (vaultKeys.version >= 3) {
        // Version 3+: Use PBKDF2-based auth hash (secure)
        const derivedAuthHash = this.deriveAuthHash(password, salt);
        passwordValid = derivedAuthHash === hash;
      } else {
        // Version 1-2: Use legacy HMAC-SHA512 hash
        const saltedHashPassword = this.encryptSHA512(password, salt);
        passwordValid = saltedHashPassword === hash;
      }

      if (!passwordValid) {
        // Password is wrong - return immediately
        return {
          canLogin: false,
        };
      }

      // Determine encryption key based on vault version
      let encryptionKey: string;
      let needsXprvMigration = false;

      if (!vaultKeys.encryptionSalt || vaultKeys.version < 2) {
        // Legacy vault format (v1) - needs migration to PBKDF2-based encryption
        console.log(
          '[KeyringManager] Detected legacy vault format (v1), migrating to v3 (PBKDF2-based encryption + auth)...',
        );

        // Store the old hash-based key temporarily for decrypting existing xprv values
        const oldHashKey = this.encryptSHA512(password, salt);
        this.legacySessionPassword = new SecureBuffer(oldHashKey);

        // Generate new encryption salt for PBKDF2
        const encryptionSalt = crypto.randomBytes(32).toString('hex');

        // Derive new encryption key using PBKDF2 (NEVER stored)
        encryptionKey = this.deriveEncryptionKey(password, encryptionSalt);

        // Derive new auth hash using PBKDF2 (stored for verification)
        const newAuthHash = this.deriveAuthHash(password, salt);

        // Update vault-keys with new encryption salt and PBKDF2 auth hash
        const updatedVaultKeys = {
          hash: newAuthHash, // Replace weak hash with PBKDF2-derived hash
          salt: vaultKeys.salt,
          encryptionSalt,
          version: 3, // v3 = PBKDF2-based encryption AND auth hash
        };
        await this.storage.set('vault-keys', updatedVaultKeys);

        // Signal that existing xprv values need to be re-encrypted
        needsXprvMigration = true;

        console.log(
          '[KeyringManager] Vault migrated to v3 (PBKDF2-based encryption + auth hash)',
        );
      } else if (vaultKeys.version === 2) {
        // Version 2: Has PBKDF2 encryption but weak auth hash - upgrade to v3
        console.log(
          '[KeyringManager] Detected v2 vault format, upgrading auth hash to PBKDF2...',
        );

        // Derive encryption key from existing salt
        encryptionKey = this.deriveEncryptionKey(
          password,
          vaultKeys.encryptionSalt,
        );

        // Derive new auth hash using PBKDF2
        const newAuthHash = this.deriveAuthHash(password, salt);

        // Update vault-keys with new PBKDF2 auth hash
        const updatedVaultKeys = {
          hash: newAuthHash, // Replace weak hash with PBKDF2-derived hash
          salt: vaultKeys.salt,
          encryptionSalt: vaultKeys.encryptionSalt,
          version: 3, // v3 = PBKDF2-based auth hash
        };
        await this.storage.set('vault-keys', updatedVaultKeys);

        console.log(
          '[KeyringManager] Vault upgraded to v3 (PBKDF2-based auth hash)',
        );
      } else {
        // Version 3+: Already using PBKDF2 for both encryption and auth
        encryptionKey = this.deriveEncryptionKey(
          password,
          vaultKeys.encryptionSalt,
        );
      }

      // Handle migration from old vault format with currentSessionSalt
      if (vaultKeys.currentSessionSalt) {
        console.log(
          '[KeyringManager] Detected old vault format, handling session migration...',
        );

        // The old format used currentSessionSalt for session data encryption
        // We need to use it temporarily to decrypt the mnemonic correctly
        const oldSessionPassword = this.encryptSHA512(
          password,
          vaultKeys.currentSessionSalt,
        );

        // Get the vault and check if mnemonic needs migration
        const { mnemonic } = await getDecryptedVault(password);

        if (mnemonic) {
          // Check if mnemonic is double-encrypted (old format behavior)
          const isLikelyPlainMnemonic =
            mnemonic.includes(' ') &&
            (mnemonic.split(' ').length === 12 ||
              mnemonic.split(' ').length === 24);

          let decryptedMnemonic = mnemonic;
          if (!isLikelyPlainMnemonic) {
            try {
              // Try to decrypt with raw password first (as vault stores it)
              decryptedMnemonic = CryptoJS.AES.decrypt(
                mnemonic,
                password,
              ).toString(CryptoJS.enc.Utf8);
            } catch (e) {
              console.warn(
                '[KeyringManager] Failed to decrypt mnemonic with password, trying old session password',
              );
              // If that fails, try with old session password
              try {
                decryptedMnemonic = CryptoJS.AES.decrypt(
                  mnemonic,
                  oldSessionPassword,
                ).toString(CryptoJS.enc.Utf8);
              } catch (e2) {
                // If both fail, assume it's already decrypted
                decryptedMnemonic = mnemonic;
              }
            }
          }

          // Re-save the vault with properly formatted mnemonic (single encryption)
          await setEncryptedVault({ mnemonic: decryptedMnemonic }, password);
          console.log('[KeyringManager] Vault mnemonic format normalized');
        }

        // Remove currentSessionSalt from vault-keys (keep other fields)
        const currentVaultKeys = await this.storage.get('vault-keys');
        const migratedVaultKeys = {
          hash: currentVaultKeys.hash,
          salt: currentVaultKeys.salt,
          encryptionSalt: currentVaultKeys.encryptionSalt,
          version: currentVaultKeys.version,
        };
        await this.storage.set('vault-keys', migratedVaultKeys);
        console.log('[KeyringManager] Old vault format migration completed');
      }

      // If session data missing or corrupted, recreate from vault
      if (!this.sessionMnemonic) {
        await this.recreateSessionFromVault(password, encryptionKey);
      }

      // NOTE: Active account management is now handled by vault state/Redux
      // No need to explicitly set active account after unlock - it's managed externally
      const vault = this.getVault();
      if (vault.activeAccount?.id !== undefined && vault.activeAccount?.type) {
        // Check if the active account actually exists in the accounts map
        const accountType = vault.activeAccount.type;
        const accountId = vault.activeAccount.id;
        const accountExists = vault.accounts?.[accountType]?.[accountId];

        if (!accountExists) {
          console.log(
            `[KeyringManager] Active account ${accountType}:${accountId} not found in accounts map. This may indicate a migration from old vault format.`,
          );
          // Signal that accounts need to be created after migration
          return {
            canLogin: true,
            needsAccountCreation: true,
            needsXprvMigration,
          };
        }

        console.log(
          `[KeyringManager] Active account ${vault.activeAccount.id} available after unlock`,
        );
      }

      return {
        canLogin: true,
        needsXprvMigration,
      };
    } catch (error) {
      console.log('ERROR unlock', {
        error,
      });
      return {
        canLogin: false,
      };
    }
  }

  public getNewChangeAddress = async (): Promise<string> => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const account = accounts[activeAccount.type]?.[activeAccount.id];
    if (!account) {
      throw new Error('Active account not found');
    }
    const { xpub, isImported, address } = account as any;
    // For imported single-address accounts, always return the single address
    const looksLikeSingleAddress = isImported && xpub === address;
    if (looksLikeSingleAddress) return address;
    return await this.getAddress(xpub, true); // Don't skip increment - get next unused
  };

  public getChangeAddress = async (id: number): Promise<string> => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const account = accounts[activeAccount.type]?.[id];
    if (!account) {
      throw new Error(`Account with id ${id} not found`);
    }
    const { xpub, isImported, address } = account as any;
    if (isImported && xpub === address) return address;
    return await this.getAddress(xpub, true);
  };

  public getPubkey = async (
    id: number,
    isChangeAddress: boolean,
  ): Promise<string> => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const account = accounts[activeAccount.type]?.[id];
    if (!account) {
      throw new Error(`Account with id ${id} not found`);
    }
    const { xpub, isImported, address } = account as any;
    // Guard: single-address imported are watch-only
    if (isImported && xpub === address) {
      throw new Error(
        'Public key not available for single-address imported accounts',
      );
    }
    // Guard: descriptor/xpub watch-only (no xprv and not hardware)
    if (this.isWatchOnlyAccount(account as any)) {
      throw new Error('Public key not available for watch-only accounts');
    }
    return await this.getCurrentAddressPubkey(xpub, isChangeAddress);
  };

  public getBip32Path = async (
    id: number,
    isChangeAddress: boolean,
  ): Promise<string> => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const account = accounts[activeAccount.type]?.[id];
    if (!account) {
      throw new Error(`Account with id ${id} not found`);
    }
    const { xpub, isImported, address } = account as any;
    // Guard: single-address imported are watch-only
    if (isImported && xpub === address) {
      throw new Error(
        'BIP32 path not available for single-address imported accounts',
      );
    }
    // Guard: descriptor/xpub watch-only (no xprv and not hardware)
    if (this.isWatchOnlyAccount(account as any)) {
      throw new Error('BIP32 path not available for watch-only accounts');
    }
    return await this.getCurrentAddressBip32Path(xpub, isChangeAddress);
  };

  public updateReceivingAddress = async (): Promise<string> => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const account = accounts[activeAccount.type]?.[activeAccount.id];
    if (!account) {
      throw new Error('Active account not found');
    }
    const { xpub, isImported, address } = account as any;
    if (isImported && xpub === address) return address;
    const nextAddress = await this.getAddress(xpub, false);
    // NOTE: Address updates should be dispatched to Redux store, not updated here
    // The calling code should handle the Redux dispatch
    return nextAddress;
  };

  public getAccountById = (
    id: number,
    accountType: KeyringAccountType,
  ): Omit<IKeyringAccountState, 'xprv'> => {
    const vault = this.getVault();
    const accounts = vault.accounts[accountType];

    const account = accounts[id];

    if (!account) {
      throw new Error('Account not found');
    }

    return omit(account as IKeyringAccountState, 'xprv');
  };

  public getPrivateKeyByAccountId = async (
    id: number,
    accountType: KeyringAccountType,
    pwd: string,
  ): Promise<string> => {
    try {
      // Validate password using vault salt (same pattern as getSeed)
      if (!this.sessionPassword) {
        throw new Error('Unlock wallet first');
      }

      // Get vault keys for password validation
      const vaultKeys = await this.storage.get('vault-keys');
      if (!vaultKeys || !vaultKeys.salt) {
        throw new Error('Vault keys not found');
      }

      // Validate password against stored auth hash (version-aware)
      if (!this.validatePassword(pwd, vaultKeys)) {
        throw new Error('Invalid password');
      }

      const vault = this.getVault();
      const account = vault.accounts[accountType][id];
      if (!account) {
        throw new Error('Account not found');
      }

      // Decrypt the stored private key using fallback method for migration support
      const decryptedPrivateKey = this.decryptXprvWithFallback(
        (account as IKeyringAccountState).xprv,
      );

      if (!decryptedPrivateKey) {
        throw new Error(
          'Failed to decrypt private key. Invalid password or corrupted data.',
        );
      }

      // NOTE: Returning decrypted private key as string is necessary for compatibility
      // Callers should handle this sensitive data carefully
      return decryptedPrivateKey;
    } catch (error) {
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  };

  public getActiveAccount = (): {
    activeAccount: Omit<IKeyringAccountState, 'xprv'>;
    activeAccountType: KeyringAccountType;
  } => {
    const vault = this.getVault();
    const { accounts, activeAccount } = vault;
    const activeAccountId = activeAccount.id;
    const activeAccountType = activeAccount.type;

    return {
      activeAccount: omit(
        accounts[activeAccountType][activeAccountId] as IKeyringAccountState,
        'xprv',
      ),
      activeAccountType,
    };
  };

  private isDescriptor = (s: string): boolean =>
    /^(addr|pkh|wpkh|sh|wsh|tr|combo|multi|sortedmulti)\s*\(/i.test(s || '');

  private isXpubLike = (s: string): boolean =>
    /^(xpub|tpub|zpub|vpub)/i.test(s || '');

  private isWatchOnlyAccount(a: IKeyringAccountState): boolean {
    if (a.isLedgerWallet || a.isTrezorWallet) return false;
    if (!a.xprv || a.xprv === '') {
      if (a.xpub === a.address) return true; // single-address imported
      if (this.isXpubLike(a.xpub) || this.isDescriptor(a.xpub)) return true; // xpub/descriptor watch-only
    }
    return false;
  }

  public getEncryptedXprv = (hd: SyscoinHDSigner) => {
    return this.withSecureData((sessionPwd) => {
      return CryptoJS.AES.encrypt(
        this.getSysActivePrivateKey(hd),
        sessionPwd,
      ).toString();
    });
  };

  public getSeed = async (pwd: string) => {
    if (!this.sessionPassword) {
      throw new Error('Unlock wallet first');
    }

    // Get vault keys for password validation
    const vaultKeys = await this.storage.get('vault-keys');
    if (!vaultKeys || !vaultKeys.salt) {
      throw new Error('Vault keys not found');
    }

    // Validate password against stored auth hash (version-aware)
    if (!this.validatePassword(pwd, vaultKeys)) {
      throw new Error('Invalid password');
    }
    let { mnemonic } = await getDecryptedVault(pwd);

    if (!mnemonic) {
      throw new Error('Mnemonic not found in vault or is empty');
    }

    // Try to detect if mnemonic is encrypted or plain text
    const isLikelyPlainMnemonic =
      mnemonic.includes(' ') &&
      (mnemonic.split(' ').length === 12 || mnemonic.split(' ').length === 24);

    if (!isLikelyPlainMnemonic) {
      try {
        mnemonic = CryptoJS.AES.decrypt(mnemonic, pwd).toString(
          CryptoJS.enc.Utf8,
        );
      } catch (decryptError) {
        // If decryption fails, assume mnemonic is already decrypted
        console.warn(
          'Mnemonic decryption failed in getSeed, using as-is:',
          decryptError.message,
        );
      }
    }

    if (!mnemonic) {
      throw new Error(
        'Failed to decrypt mnemonic or mnemonic is empty after decryption',
      );
    }

    return mnemonic;
  };

  public setSignerNetwork = async (
    network: INetwork,
  ): Promise<{
    activeChain?: INetworkType;
    success: boolean;
  }> => {
    // With multi-keyring architecture, each keyring is dedicated to specific slip44
    if (
      INetworkType.Ethereum !== network.kind &&
      INetworkType.Syscoin !== network.kind
    ) {
      throw new Error('Unsupported chain');
    }

    // Validate network/chain type compatibility
    if (
      network.kind === INetworkType.Ethereum &&
      this.getActiveChain() === INetworkType.Syscoin
    ) {
      throw new Error('Cannot use Ethereum chain type with Syscoin network');
    }
    if (
      network.kind === INetworkType.Syscoin &&
      this.getActiveChain() === INetworkType.Ethereum
    ) {
      throw new Error('Cannot use Syscoin chain type with Ethereum network');
    }

    // CRITICAL: Prevent UTXO-to-UTXO network switching within same keyring
    // Each UTXO network should have its own KeyringManager instance based on slip44
    const vault = this.getVault();
    if (this.getActiveChain() === INetworkType.Syscoin && vault.activeNetwork) {
      const currentSlip44 = vault.activeNetwork.slip44;
      const newSlip44 = network.slip44;

      if (currentSlip44 !== newSlip44) {
        throw new Error(
          `Cannot switch between different UTXO networks within the same keyring. ` +
          `Current network uses slip44=${currentSlip44}, target network uses slip44=${newSlip44}. ` +
          `Each UTXO network requires a separate KeyringManager instance.`,
        );
      }
    }

    try {
      // With multi-keyring architecture:
      // - UTXO: Each keyring is dedicated to one network (slip44), so this is only called during initialization
      // - EVM: All EVM networks share slip44=60, so network can change within the same keyring

      if (network.kind === INetworkType.Syscoin) {
        // For UTXO networks: validate that active account exists (accounts should be created via addNewAccount/initialize)
        const accountId = vault.activeAccount.id || 0;
        const accountType =
          vault.activeAccount.type || KeyringAccountType.HDAccount;
        const accounts = vault.accounts[accountType];

        if (!accounts[accountId] || !accounts[accountId].xpub) {
          throw new Error(
            `Active account ${accountType}:${accountId} does not exist. Create accounts using addNewAccount() or initializeWalletSecurely() first.`,
          );
        }

        // No additional setup needed - on-demand signers will be created when needed
      } else if (network.kind === INetworkType.Ethereum) {
        // For EVM networks: validate that active account exists
        const accountId = vault.activeAccount.id || 0;
        const accountType =
          vault.activeAccount.type || KeyringAccountType.HDAccount;
        const accounts = vault.accounts[accountType];

        if (!accounts[accountId] || !accounts[accountId].xpub) {
          throw new Error(
            `Active account ${accountType}:${accountId} does not exist. Create accounts using addNewAccount() or initializeWalletSecurely() first.`,
          );
        }

        // Set up EVM provider for network switching
        await this.setSignerEVM(network);
      }

      return {
        success: true,
      };
    } catch (err) {
      console.log('ERROR setSignerNetwork', {
        err,
      });

      this.validateAndHandleErrorByMessage(err.message);

      //Rollback to previous values
      console.error('Set Signer Network failed with', err);
      return { success: false };
    }
  };

  public forgetMainWallet = async (pwd: string) => {
    const vaultKeys = await this.storage.get('vault-keys');
    if (!vaultKeys || !vaultKeys.salt) {
      throw new Error('Vault keys not found');
    }
    if (!this.sessionPassword) {
      throw new Error('Unlock wallet first');
    }

    // Validate password against stored auth hash (version-aware)
    if (!this.validatePassword(pwd, vaultKeys)) {
      throw new Error('Invalid password');
    }

    await this.clearTemporaryLocalKeys(pwd);
  };

  public importWeb3Account = (mnemonicOrPrivKey: string) => {
    // Check if it's a hex string (Ethereum private key)
    if (isHexString(mnemonicOrPrivKey)) {
      return new Wallet(mnemonicOrPrivKey);
    }

    // Check if it's a zprv/tprv (Syscoin private key)
    const zprvPrefixes = ['zprv', 'tprv', 'vprv', 'xprv'];
    if (zprvPrefixes.some((prefix) => mnemonicOrPrivKey.startsWith(prefix))) {
      throw new Error(
        'Syscoin extended private keys (zprv/tprv) should be imported using importAccount, not importWeb3Account',
      );
    }

    // Otherwise, assume it's a mnemonic
    const account = Wallet.fromMnemonic(mnemonicOrPrivKey);

    return account;
  };

  public getAccountXpub = (): string => {
    const vault = this.getVault();
    const { activeAccount } = vault;
    const account = vault.accounts[activeAccount.type]?.[activeAccount.id];
    if (!account) {
      throw new Error('Active account not found');
    }
    return account.xpub;
  };

  public isSeedValid = (seedPhrase: string) =>
    BIP84.validateMnemonic(seedPhrase);

  public createNewSeed = (wordCount?: number) => {
    // Map BIP39 word counts to entropy strength
    const wordCountToStrength: Record<number, number> = {
      12: 128,
      15: 160,
      18: 192,
      21: 224,
      24: 256,
    };
    const strength = wordCount ? wordCountToStrength[wordCount] : 128;
    return strength
      ? BIP84.generateMnemonic(strength)
      : BIP84.generateMnemonic();
  };

  public getUTXOState = () => {
    const vault = this.getVault();
    if (vault.activeNetwork.kind !== INetworkType.Syscoin) {
      throw new Error('Cannot get state in a ethereum network');
    }

    const utxOAccounts = mapValues(vault.accounts.HDAccount, (value) =>
      omit(value, 'xprv'),
    );

    return {
      ...vault,
      accounts: {
        [KeyringAccountType.HDAccount]: utxOAccounts,
        [KeyringAccountType.Imported]: {},
        [KeyringAccountType.Trezor]: {},
        [KeyringAccountType.Ledger]: {},
      },
    };
  };

  public async importTrezorAccount(label?: string) {
    const vault = this.getVault();
    const currency = vault.activeNetwork.currency;
    if (!currency) {
      throw new Error('Active network currency is not defined');
    }

    // Use getNextAccountId to filter out placeholder accounts
    const nextIndex = this.getNextAccountId(
      vault.accounts[KeyringAccountType.Trezor],
    );

    const importedAccount = await this._createTrezorAccount(
      currency,
      vault.activeNetwork.slip44,
      nextIndex,
    );
    importedAccount.label = label ? label : `Trezor ${importedAccount.id + 1}`;

    // NOTE: Account creation should be dispatched to Redux store, not updated here
    // The calling code should handle the Redux dispatch
    // Return the created account for Pali to add to store
    return importedAccount;
  }

  public async importLedgerAccount(label?: string) {
    try {
      const vault = this.getVault();
      const currency = vault.activeNetwork.currency;
      if (!currency) {
        throw new Error('Active network currency is not defined');
      }

      // Use getNextAccountId to filter out placeholder accounts
      const nextIndex = this.getNextAccountId(
        vault.accounts[KeyringAccountType.Ledger],
      );

      const importedAccount = await this._createLedgerAccount(
        currency,
        vault.activeNetwork.slip44,
        nextIndex,
      );
      importedAccount.label = label
        ? label
        : `Ledger ${importedAccount.id + 1}`;

      // NOTE: Account creation should be dispatched to Redux store, not updated here
      // The calling code should handle the Redux dispatch
      // Return the created account for Pali to add to store
      return importedAccount;
    } catch (error) {
      console.log({ error });
      throw error;
    }
  }

  public getActiveUTXOAccountState = () => {
    const vault = this.getVault();
    const { activeAccount } = vault;
    return {
      ...vault.accounts.HDAccount[activeAccount.id],
      xprv: undefined,
    };
  };

  public getNetwork = () => this.getVault().activeNetwork;

  public createEthAccount = (privateKey: string) => new Wallet(privateKey);

  // Helper to get current account data from backend
  private fetchCurrentAccountData = async (
    xpub: string,
    isChangeAddress: boolean,
  ) => {
    const vault = this.getVault();
    const { activeNetwork } = vault;

    // Use read-only signer for backend calls - works for all account types including hardware wallets
    const { main } = this.getReadOnlySigner();
    const options = 'tokens=used&details=tokens';

    const { tokens } = await syscoinjs.utils.fetchBackendAccount(
      main.blockbookURL,
      xpub,
      options,
      true,
      undefined,
    );

    const { receivingIndex, changeIndex } =
      this.setLatestIndexesFromXPubTokens(tokens);

    // Get network configuration for BIP84 using network-provided pub type macros
    const networkConfig = getNetworkConfig(
      activeNetwork.slip44,
      activeNetwork.currency,
    );

    const pubTypes = networkConfig?.types?.zPubType;
    if (!pubTypes) {
      throw new Error('Missing zPubType in network configuration');
    }
    const networks = networkConfig.networks;

    const currentAccount = new BIP84.fromZPub(xpub, pubTypes, networks);

    const addressIndex = isChangeAddress ? changeIndex : receivingIndex;

    return {
      currentAccount,
      addressIndex,
      main,
    };
  };

  public getAddress = async (
    xpub: string,
    isChangeAddress: boolean,
    options?: { forceIndex0?: boolean },
  ) => {
    const { currentAccount, addressIndex } = await this.fetchCurrentAccountData(
      xpub,
      isChangeAddress,
    );

    const effectiveIndex = options?.forceIndex0 ? 0 : addressIndex;

    const address = currentAccount.getAddress(
      effectiveIndex,
      isChangeAddress,
      84,
    ) as string;

    return address;
  };

  public getCurrentAddressPubkey = async (
    xpub: string,
    isChangeAddress: boolean,
  ): Promise<string> => {
    const { currentAccount, addressIndex } = await this.fetchCurrentAccountData(
      xpub,
      isChangeAddress,
    );

    // BIP84 returns the public key as a hex string directly
    return currentAccount.getPublicKey(addressIndex, isChangeAddress);
  };

  public getCurrentAddressBip32Path = async (
    xpub: string,
    isChangeAddress: boolean,
  ): Promise<string> => {
    const vault = this.getVault();
    const { activeAccount, activeNetwork } = vault;

    const { addressIndex } = await this.fetchCurrentAccountData(
      xpub,
      isChangeAddress,
    );

    // Use the utility function to generate the proper derivation path
    const coinShortcut = activeNetwork.currency.toLowerCase(); // e.g., 'sys', 'btc'
    const path = getAddressDerivationPath(
      coinShortcut,
      activeNetwork.slip44,
      activeAccount.id,
      isChangeAddress,
      addressIndex,
    );

    return path;
  };

  public logout = () => {
    this.lockWallet();
  };

  public async importAccount(
    privKey: string,
    label?: string,
    options?: { utxoAddressType?: 'p2wpkh' | 'p2pkh' | 'p2tr' },
  ) {
    // Check if wallet is unlocked
    if (!this.isUnlocked()) {
      throw new Error('Wallet must be unlocked to import accounts');
    }

    const importedAccount = await this._getPrivateKeyAccountInfos(
      privKey,
      label,
      options,
    );

    // NOTE: Account creation should be dispatched to Redux store, not updated here
    // The calling code should handle the Redux dispatch
    // Return the created account for Pali to add to store
    return importedAccount;
  }

  // Import a WIF on UTXO networks and force legacy P2PKH address/type.
  // Keeps it as a single-address Imported account, storing the address in both xpub and address.

  public async importWatchOnly(identifier: string, label?: string) {
    // Validate via Blockbook and create a watch-only Imported account
    const vault = this.getVault();
    const { accounts, activeNetwork } = vault;

    if (!identifier || typeof identifier !== 'string') {
      throw new Error('Identifier is required');
    }

    const isXpub = this.isXpubLike(identifier);
    const isDesc = this.isDescriptor(identifier);
    const isAddress = !isXpub && !isDesc;

    // Compute address field
    let addressToStore = identifier;
    if (isXpub) {
      // Minimal approach: treat any extended pubkey as BIP84 by converting to zpub/vpub
      try {
        const { types } = getNetworkConfig(
          activeNetwork.slip44,
          activeNetwork.currency || 'Syscoin',
        );
        const target =
          activeNetwork.slip44 === 1
            ? (types.zPubType as any).testnet.vpub
            : types.zPubType.mainnet.zpub;
        const bip84Key = convertExtendedKeyVersion(identifier, target);
        addressToStore = await this.getAddress(bip84Key, false, {
          forceIndex0: true,
        });
      } catch (e) {
        // Fallback to identifier if derivation fails (e.g., malformed)
        addressToStore = identifier;
      }
    }

    // Validate duplicates
    const existsInImported = Object.values(
      accounts[KeyringAccountType.Imported] as IKeyringAccountState[],
    ).some((a) => a.address === addressToStore);
    const existsInHD = Object.values(
      accounts[KeyringAccountType.HDAccount] as IKeyringAccountState[],
    ).some((a) => a.address === addressToStore);
    if (existsInImported || existsInHD) {
      throw new Error('Account already exists on your Wallet.');
    }
    // Confirm with Blockbook
    const options = 'details=basic';
    // Validate against Blockbook directly to capture precise error details (e.g., checksum mismatch)
    const baseUrl = activeNetwork.url.replace(/\/$/, '');
    const path = isXpub || isDesc ? '/api/v2/xpub/' : '/api/v2/address/';
    const url = `${baseUrl}${path}${encodeURIComponent(identifier)}?${options}`;
    let res: any = null;
    try {
      const response = await fetch(url);
      if (!response.ok) {
        let errorText = response.statusText || 'Request failed';
        try {
          const bodyText = await response.text();
          if (bodyText) {
            try {
              const json = JSON.parse(bodyText);
              if (json && json.error) {
                errorText = json.error;
              } else {
                errorText = bodyText;
              }
            } catch {
              errorText = bodyText;
            }
          }
        } catch (parseError) {
          // ignore body parse error; fall back to statusText
        }
        throw new Error(errorText);
      }
      res = await response.json();
    } catch (e: any) {
      throw new Error(e?.message || 'Identifier validation failed');
    }
    if (!res) {
      throw new Error('Identifier not found on the active network');
    }

    const id = this.getNextAccountId(accounts[KeyringAccountType.Imported]);
    const defaultLabel = label || `Watch-only ${id + 1}`;

    const balances = { syscoin: 0, ethereum: 0 };

    const watchOnlyAccount = {
      ...initialActiveImportedAccountState,
      address: addressToStore,
      label: defaultLabel,
      id,
      balances,
      isImported: true,
      xprv: '',
      xpub: isAddress ? addressToStore : identifier,
      assets: {
        syscoin: [],
        ethereum: [],
      },
    } as IKeyringAccountState;

    return watchOnlyAccount;
  }

  public validateZprv(zprv: string, targetNetwork?: INetwork) {
    // Use the active network if targetNetwork is not provided
    const networkToValidateAgainst =
      targetNetwork || this.getVault().activeNetwork;

    if (!networkToValidateAgainst) {
      throw new Error('No network available for validation');
    }

    try {
      // Check if it looks like an extended key based on known prefixes
      const knownExtendedKeyPrefixes = [
        'xprv',
        'xpub',
        'yprv',
        'ypub',
        'zprv',
        'zpub',
        'tprv',
        'tpub',
        'uprv',
        'upub',
        'vprv',
        'vpub',
      ];
      const prefix = zprv.substring(0, 4);
      const looksLikeExtendedKey = knownExtendedKeyPrefixes.includes(prefix);

      // Only check prefix validity if it looks like an extended key
      if (looksLikeExtendedKey) {
        const validBip84Prefixes = ['zprv', 'vprv']; // zprv for mainnet, vprv for testnet
        if (!validBip84Prefixes.includes(prefix)) {
          throw new Error(
            `Invalid key prefix '${prefix}'. Only BIP84 keys (zprv/vprv) are supported for UTXO imports. BIP44 keys (xprv/tprv) are not supported.`,
          );
        }
      } else {
        // Not an extended key format
        throw new Error('Not an extended private key');
      }

      const bip32 = BIP32Factory(ecc);
      const decoded = bs58check.decode(zprv);

      if (decoded.length !== 78) {
        throw new Error('Invalid length for a BIP-32 key');
      }

      // Get network configuration for the target network
      const { networks, types } = getNetworkConfig(
        networkToValidateAgainst.slip44,
        networkToValidateAgainst.currency || 'Bitcoin',
      );

      // For BIP84 (zprv/zpub), we need to use the correct magic bytes from zPubType
      // Determine key type: zprv = mainnet key, vprv = testnet key
      const keyIsTestnet = prefix === 'vprv';

      // Determine target network type: testnet networks typically have slip44 1
      const targetIsTestnet = networkToValidateAgainst.slip44 === 1;

      // Cross-network validation: reject if key type doesn't match target network
      if (keyIsTestnet && !targetIsTestnet) {
        throw new Error(
          `Extended private key is not compatible with ${networkToValidateAgainst.label}. ` +
          `This appears to be a testnet key (${prefix}) but the target network is mainnet.`,
        );
      }

      if (!keyIsTestnet && targetIsTestnet) {
        throw new Error(
          `Extended private key is not compatible with ${networkToValidateAgainst.label}. ` +
          `This appears to be a mainnet key (${prefix}) but the target network is testnet.`,
        );
      }

      const pubTypes = keyIsTestnet
        ? (types.zPubType as any).testnet
        : types.zPubType.mainnet;
      const baseNetwork = keyIsTestnet ? networks.testnet : networks.mainnet;

      const network = {
        ...baseNetwork,
        bip32: {
          public: parseInt(pubTypes.vpub || pubTypes.zpub, 16),
          private: parseInt(pubTypes.vprv || pubTypes.zprv, 16),
        },
      };

      // Validate that the key prefix matches the expected network format
      // This ensures the key was generated for a compatible network
      const expectedPrefixes = ['zprv', 'vprv', 'xprv', 'yprv']; // Accept various BIP32/84 formats
      if (!expectedPrefixes.includes(prefix)) {
        throw new Error(
          `Invalid extended private key prefix: ${prefix}. Expected one of: ${expectedPrefixes.join(
            ', ',
          )}`,
        );
      }

      // Strict network matching - only allow keys that match the target network
      let node;
      try {
        node = bip32.fromBase58(zprv, network);
      } catch (e) {
        throw new Error(
          `Extended private key is not compatible with ${networkToValidateAgainst.label}. Please use a key generated for this specific network.`,
        );
      }

      if (!node.privateKey) {
        throw new Error('Private key not found in extended private key');
      }
      if (!ecc.isPrivate(node.privateKey)) {
        throw new Error('Invalid private key for secp256k1 curve');
      }

      return {
        isValid: true,
        node,
        network,
        message: 'The extended private key is valid for this network.',
      };
    } catch (error) {
      return { isValid: false, message: error.message };
    }
  }

  public validateWif(wif: string, targetNetwork?: INetwork) {
    // Use the active network if targetNetwork is not provided
    const networkToValidateAgainst =
      targetNetwork || this.getVault().activeNetwork;

    if (!networkToValidateAgainst) {
      throw new Error('No network available for validation');
    }

    try {
      // Get bitcoinjs network for the target network (Syscoin/BTC etc.)
      const { networks } = getNetworkConfig(
        networkToValidateAgainst.slip44,
        networkToValidateAgainst.currency || 'Bitcoin',
      );

      const isTestnet = networkToValidateAgainst.slip44 === 1;
      const bitcoinNetwork = isTestnet ? networks.testnet : networks.mainnet;

      // Try to parse the WIF for the given network
      const keyPair = (syscoinjs.utils as any).bitcoinjs.ECPair.fromWIF(
        wif,
        bitcoinNetwork,
      );
      if (!keyPair || !keyPair.privateKey)
        throw new Error('Invalid WIF private key');

      // Derive an address based on network capability
      // Try different address types to ensure the key can derive addresses
      let address: string | undefined;
      try {
        // Try P2TR (Taproot) first if bech32 is supported
        if ((bitcoinNetwork as any).bech32) {
          try {
            address = bjs.payments.p2wpkh({
              pubkey: keyPair.publicKey,
              network: bitcoinNetwork,
            }).address as string | undefined;
          } catch (e) {
            // P2TR might not be supported, try P2WPKH
          }
        }
        if (!address) {
          address = bjs.payments.p2pkh({
            pubkey: keyPair.publicKey,
            network: bitcoinNetwork,
          }).address as string | undefined;
        }
      } catch (e) {
        // ignore and handle below
      }
      if (!address) throw new Error('Failed to derive address from WIF');

      return { isValid: true };
    } catch (error) {
      return { isValid: false, message: error.message };
    }
  }

  /**
   * PRIVATE METHODS
   */

    // ===================================== AUXILIARY METHOD - FOR TRANSACTIONS CLASSES ===================================== //
  private getDecryptedPrivateKey = (): {
    address: string;
    decryptedPrivateKey: string;
  } => {
    try {
      const vault = this.getVault();
      const { accounts, activeAccount } = vault;
      const activeAccountId = activeAccount.id;
      const activeAccountType = activeAccount.type;
      const isLedger = activeAccountType === KeyringAccountType.Ledger;
      const isTrezor = activeAccountType === KeyringAccountType.Trezor;

      const isHardwareWallet = isTrezor || isLedger;

      if (!this.sessionPassword)
        throw new Error('Wallet is locked cant proceed with transaction');

      const activeAccountData = accounts[activeAccountType][activeAccountId];
      if (!activeAccountData) {
        throw new Error(
          `Active account (${activeAccountType}:${activeAccountId}) not found. Account switching may be in progress.`,
        );
      }

      const { xprv, address } = activeAccountData;

      if (isHardwareWallet) {
        return {
          address,
          decryptedPrivateKey: '',
        };
      }

      if (!xprv) {
        throw new Error(
          `Private key not found for account ${activeAccountType}:${activeAccountId}. Account may not be fully initialized.`,
        );
      }

      let decryptedPrivateKey: string;
      try {
        // Use fallback decryption for migration support
        decryptedPrivateKey = this.decryptXprvWithFallback(xprv);
      } catch (decryptError) {
        throw new Error(
          `Failed to decrypt private key for account ${activeAccountType}:${activeAccountId}. The wallet may be locked or corrupted.`,
        );
      }

      if (!decryptedPrivateKey) {
        throw new Error(
          `Decrypted private key is empty for account ${activeAccountType}:${activeAccountId}. Invalid password or corrupted data.`,
        );
      }

      // For EVM accounts, validate that the derived address matches the stored address
      // This helps catch account switching race conditions early
      if (this.getActiveChain() === INetworkType.Ethereum) {
        try {
          const derivedWallet = new Wallet(decryptedPrivateKey);
          if (derivedWallet.address.toLowerCase() !== address.toLowerCase()) {
            throw new Error(
              `Address mismatch for account ${activeAccountType}:${activeAccountId}. Expected ${address} but derived ${derivedWallet.address}. Account switching may be in progress.`,
            );
          }
        } catch (ethersError) {
          throw new Error(
            `Failed to validate EVM address for account ${activeAccountType}:${activeAccountId}: ${ethersError.message}`,
          );
        }
      }

      return {
        address,
        decryptedPrivateKey,
      };
    } catch (error) {
      const vaultForLogging = this.getVault();
      console.error('ERROR getDecryptedPrivateKey', {
        error: error.message,
        activeChain: this.getActiveChain(),
        vault: {
          activeAccountId: vaultForLogging?.activeAccount?.id,
          activeAccountType: vaultForLogging?.activeAccount?.type,
        },
      });
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  };

  private getSigner = (): {
    hd: any; // SyscoinHDSigner or WIFSigner wrapper with sign(psbt)
    main: any; // syscoinjs-lib Syscoin instance
  } => {
    if (!this.sessionPassword) {
      throw new Error('Wallet is locked cant proceed with transaction');
    }
    if (this.getActiveChain() !== INetworkType.Syscoin) {
      throw new Error('Switch to UTXO chain');
    }

    const vault = this.getVault();
    const { activeAccount } = vault;
    const accountId = activeAccount.id;
    const accountType = activeAccount.type;

    // Determine signer type: HD or WIF single-address
    let signerForUse: any;
    if (accountType === KeyringAccountType.HDAccount) {
      signerForUse = this.createOnDemandUTXOSigner(accountId);
    } else if (accountType === KeyringAccountType.Imported) {
      // Decrypt stored key material using fallback for migration support
      const account = vault.accounts[KeyringAccountType.Imported][accountId];
      const decrypted = this.decryptXprvWithFallback(account.xprv);

      if (this.isZprv(decrypted)) {
        signerForUse = this.createFreshUTXOSigner(decrypted, accountId);
      } else {
        // Treat as WIF single-address signer wrapper exposing sign(psbt)
        const network = vault.activeNetwork;
        const { networks } = getNetworkConfig(network.slip44, network.currency);
        const isTestnet = network.slip44 === 1;
        const bitcoinjsNetwork = isTestnet
          ? networks.testnet
          : networks.mainnet;

        signerForUse = {
          sign: async (psbt: Psbt) => {
            return await (syscoinjs.utils as any).signWithWIF(
              psbt,
              decrypted,
              bitcoinjsNetwork,
            );
          },
        };
      }
    } else {
      throw new Error(
        `Unsupported account type for UTXO signing: ${accountType}`,
      );
    }

    // Create syscoinjs instance with current network (no need to attach signer for signing flow)
    const network = vault.activeNetwork;
    const networkConfig = getNetworkConfig(network.slip44, network.currency);
    const isTestnet = network.slip44 === 1;
    const bitcoinjsNetwork = isTestnet
      ? networkConfig?.networks?.testnet
      : networkConfig?.networks?.mainnet;

    const syscoinMainSigner = new syscoinjs.SyscoinJSLib(
      null,
      network.url,
      bitcoinjsNetwork,
    );

    return {
      hd: signerForUse,
      main: syscoinMainSigner,
    };
  };

  // Read-only version that works when wallet is locked
  private getReadOnlySigner = (): {
    main: any; // syscoinjs-lib Syscoin instance (read-only)
  } => {
    if (this.getActiveChain() !== INetworkType.Syscoin) {
      throw new Error('Switch to UTXO chain');
    }

    // Create syscoinjs instance without HD signer for read-only operations
    const vault = this.getVault();
    const network = vault.activeNetwork;
    const networkConfig = getNetworkConfig(network.slip44, network.currency);
    const isTestnet = network.slip44 === 1;
    const bitcoinjsNetwork = isTestnet
      ? networkConfig?.networks?.testnet
      : networkConfig?.networks?.mainnet;

    const syscoinMainSigner = new syscoinjs.SyscoinJSLib(
      null, // No HD signer needed for read-only operations
      network.url,
      bitcoinjsNetwork,
    );

    return {
      main: syscoinMainSigner,
    };
  };

  private validateAndHandleErrorByMessage(message: string) {
    const utf8ErrorMessage = 'Malformed UTF-8 data';
    if (
      message.includes(utf8ErrorMessage) ||
      message.toLowerCase().includes(utf8ErrorMessage.toLowerCase())
    ) {
      this.storage.set('utf8Error', { hasUtf8Error: true });
    }
  }

  private getAccountsState = () => {
    const vault = this.getVault();
    const { accounts, activeAccount, activeNetwork } = vault;
    return {
      activeAccountId: activeAccount.id,
      accounts,
      activeAccountType: activeAccount.type,
      activeNetwork,
    };
  };

  /**
   *
   * @param password
   * @param salt
   * @returns hash: string
   */
  private encryptSHA512 = (password: string, salt: string) =>
    crypto.createHmac('sha512', salt).update(password).digest('hex');

  /**
   * Derives a secure encryption key from password using PBKDF2.
   * This key is NEVER stored - only computed when needed and kept in memory.
   *
   * @param password - The user's password
   * @param salt - A unique salt for key derivation (different from auth salt)
   * @returns A derived key suitable for AES encryption
   */
  private deriveEncryptionKey = (password: string, salt: string): string => {
    // PBKDF2 with SHA-512, 100,000 iterations, 256-bit output
    // This makes brute-force attacks computationally expensive
    const key = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
      keySize: 256 / 32, // 256 bits = 8 words (32 bits per word in CryptoJS)
      iterations: 100000,
      hasher: CryptoJS.algo.SHA512,
    });
    return key.toString();
  };

  /**
   * Derives a secure authentication hash from password using PBKDF2.
   * This replaces the weak HMAC-SHA512 single-pass hash for vault version 3+.
   * The resulting hash is stored in vault-keys for password verification.
   *
   * Uses 120,000 iterations (slightly more than encryption key derivation)
   * to ensure password verification is also computationally expensive for attackers.
   *
   * @param password - The user's password
   * @param salt - A unique salt for authentication (stored in vault-keys)
   * @returns A derived hash suitable for password verification
   */
  private deriveAuthHash = (password: string, salt: string): string => {
    // PBKDF2 with SHA-512, 120,000 iterations, 512-bit output
    // Slightly more iterations than encryption key to add extra protection
    // for the stored authentication hash
    const hash = CryptoJS.PBKDF2(password, CryptoJS.enc.Hex.parse(salt), {
      keySize: 512 / 32, // 512 bits = 16 words
      iterations: 120000,
      hasher: CryptoJS.algo.SHA512,
    });
    return hash.toString();
  };

  /**
   * Validates a password against the stored auth hash.
   * Uses the appropriate hashing method based on vault version.
   *
   * @param password - The password to validate
   * @param vaultKeys - The vault keys containing hash, salt, and version
   * @returns true if password is valid, false otherwise
   */
  private validatePassword = (
    password: string,
    vaultKeys: { hash: string; salt: string; version?: number },
  ): boolean => {
    if (vaultKeys?.version && vaultKeys.version >= 3) {
      // Version 3+: Use PBKDF2-based auth hash (secure)
      const derivedAuthHash = this.deriveAuthHash(password, vaultKeys.salt);
      return derivedAuthHash === vaultKeys.hash;
    } else {
      // Version 1-2: Use legacy HMAC-SHA512 hash
      const saltedHashPassword = this.encryptSHA512(password, vaultKeys.salt);
      return saltedHashPassword === vaultKeys.hash;
    }
  };

  private getSysActivePrivateKey = (hd: SyscoinHDSigner) => {
    if (hd === null) throw new Error('No HD Signer');

    const accountIndex = hd.Signer.accountIndex;

    // Verify the account exists now
    if (!hd.Signer.accounts.has(accountIndex)) {
      throw new Error(`Account at index ${accountIndex} could not be created`);
    }

    return hd.Signer.accounts.get(accountIndex).getAccountPrivateKey();
  };

  private getInitialAccountData = ({
                                     label,
                                     signer,
                                     sysAccount,
                                     xprv,
                                   }: {
    label?: string;
    signer: any;
    sysAccount: ISysAccount;
    xprv: string;
  }) => {
    const { address, xpub } = sysAccount;

    return {
      id: signer.Signer.accountIndex,
      label: label || `Account ${signer.Signer.accountIndex + 1}`,
      xpub,
      xprv,
      address,
      isTrezorWallet: false,
      isLedgerWallet: false,
      isImported: false,
    };
  };

  private async _createTrezorAccount(
    coin: string,
    slip44: number,
    index: number,
    label?: string,
  ) {
    const vault = this.getVault();
    const { accounts } = vault;

    // For EVM networks, Trezor expects 'eth' regardless of the network's currency
    const trezorCoin = slip44 === 60 ? 'eth' : coin;

    const { descriptor, balance: _balance } =
      await this.trezorSigner.getAccountInfo({
        coin: trezorCoin,
        slip44,
        index,
      });
    const xpub = descriptor;
    const balance = _balance;

    let ethPubKey = '';

    const isEVM = isEvmCoin(coin, slip44);

    // For EVM networks, we need to get the actual address from Trezor
    let address: string;
    if (isEVM) {
      // For EVM, the descriptor from getAccountInfo is the address
      address = xpub;

      // Get the public key for EVM
      const response = await this.trezorSigner.getPublicKey({
        coin: trezorCoin,
        slip44,
        index: +index,
      });
      ethPubKey = response.publicKey;
    } else {
      // For UTXO, use the xpub to derive the address
      // Always use first receive address (index 0) for imported account display
      address = await this.getAddress(xpub, false, { forceIndex0: true });
    }

    const accountAlreadyExists =
      Object.values(
        accounts[KeyringAccountType.Ledger] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.Trezor] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.HDAccount] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.Imported] as IKeyringAccountState[],
      ).some((account) => account.address === address);

    if (accountAlreadyExists)
      throw new Error('Account already exists on your Wallet.');
    if (!xpub || !address)
      throw new Error(
        'Something wrong happened. Please, try again or report it',
      );

    // Use getNextAccountId to properly handle placeholder accounts
    const id = this.getNextAccountId(accounts[KeyringAccountType.Trezor]);

    // Convert balance from satoshis to SYS safely
    // Using string manipulation to avoid precision loss
    let syscoinBalance = 0;
    if (!isEVM && balance) {
      const balanceStr = balance.toString();
      // Handle conversion without division to preserve precision
      if (balanceStr.length > 8) {
        // Has whole SYS part
        const wholePart = balanceStr.slice(0, -8);
        const decimalPart = balanceStr.slice(-8);
        syscoinBalance = parseFloat(`${wholePart}.${decimalPart}`);
      } else {
        // Less than 1 SYS
        const paddedBalance = balanceStr.padStart(8, '0');
        syscoinBalance = parseFloat(`0.${paddedBalance}`);
      }
    }

    const trezorAccount = {
      ...this.initialTrezorAccountState,
      balances: {
        syscoin: isEVM ? 0 : syscoinBalance,
        ethereum: 0,
      },
      address,
      label: label ? label : `Trezor ${id + 1}`,
      id,
      xprv: '',
      xpub: isEVM ? ethPubKey : xpub,
      assets: {
        syscoin: [],
        ethereum: [],
      },
    } as IKeyringAccountState;

    return trezorAccount;
  }

  private async _createLedgerAccount(
    coin: string,
    slip44: number,
    index: number,
    label?: string,
  ) {
    const vault = this.getVault();
    const { accounts } = vault;
    let xpub;
    let address = '';
    if (isEvmCoin(coin, slip44)) {
      const { address: ethAddress, publicKey } =
        await this.ledgerSigner.evm.getEvmAddressAndPubKey({
          accountIndex: index,
        });
      address = ethAddress;
      xpub = publicKey;
    } else {
      const ledgerXpub = await this.ledgerSigner.utxo.getXpub({
        index: index,
        coin,
        slip44,
      });

      // Convert device-returned extended key to BIP84 zpub/vpub for storage/backend usage
      const { types } = getNetworkConfig(slip44, coin);
      const bip84Target =
        slip44 === 1
          ? (types.zPubType as any).testnet.vpub
          : types.zPubType.mainnet.zpub;
      xpub = convertExtendedKeyVersion(ledgerXpub, bip84Target);

      // Always use first receive address (index 0) for imported account display
      address = await this.getAddress(xpub, false, { forceIndex0: true });
    }

    const accountAlreadyExists =
      Object.values(
        accounts[KeyringAccountType.Ledger] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.Trezor] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.HDAccount] as IKeyringAccountState[],
      ).some((account) => account.address === address) ||
      Object.values(
        accounts[KeyringAccountType.Imported] as IKeyringAccountState[],
      ).some((account) => account.address === address);

    if (accountAlreadyExists)
      throw new Error('Account already exists on your Wallet.');
    if (!xpub || !address)
      throw new Error(
        'Something wrong happened. Please, try again or report it',
      );

    // Use getNextAccountId to properly handle placeholder accounts
    const id = this.getNextAccountId(accounts[KeyringAccountType.Ledger]);

    const currentBalances = { syscoin: 0, ethereum: 0 };

    const ledgerAccount = {
      ...this.initialLedgerAccountState,
      balances: currentBalances,
      address,
      label: label ? label : `Ledger ${id + 1}`,
      id,
      xprv: '',
      xpub,
      assets: {
        syscoin: [],
        ethereum: [],
      },
    } as IKeyringAccountState;

    return ledgerAccount;
  }

  private getFormattedBackendAccount = async ({
                                                signer,
                                              }: {
    signer: SyscoinHDSigner;
  }): Promise<ISysAccount> => {
    // MUCH SIMPLER: Just use the signer directly - no BIP84 needed!
    // Get address directly from the signer (always correct for current network)
    const address = signer.createAddress(0, false, 84) as string;
    const xpub = signer.getAccountXpub();

    return {
      address,
      xpub,
    };
  };
  private setLatestIndexesFromXPubTokens = function(tokens) {
    let changeIndexInternal = -1,
      receivingIndexInternal = -1;
    if (tokens) {
      tokens.forEach((token) => {
        if (!token.transfers || !token.path) {
          return {
            changeIndex: changeIndexInternal + 1,
            receivingIndex: receivingIndexInternal + 1,
          };
        }
        const transfers = parseInt(token.transfers, 10);
        if (token.path && transfers > 0) {
          const splitPath = token.path.split('/');
          if (splitPath.length >= 6) {
            const change = parseInt(splitPath[4], 10);
            const index = parseInt(splitPath[5], 10);
            if (change === 1) {
              if (index > changeIndexInternal) {
                changeIndexInternal = index;
              }
            } else if (index > receivingIndexInternal) {
              receivingIndexInternal = index;
            }
          }
        }
      });
    }
    return {
      changeIndex: changeIndexInternal + 1,
      receivingIndex: receivingIndexInternal + 1,
    };
  };

  // Common helper method for UTXO account creation
  private async createUTXOAccountAtIndex(accountId: number, label?: string) {
    try {
      // Create fresh signer just for this account creation operation
      const freshHDSigner = this.createOnDemandUTXOSigner(accountId);

      const sysAccount = await this.getFormattedBackendAccount({
        signer: freshHDSigner,
      });

      const encryptedXprv = this.getEncryptedXprv(freshHDSigner);

      // Generate network-aware label if none provided
      const vault = this.getVault();
      const network = vault.activeNetwork;
      const defaultLabel = this.generateNetworkAwareLabel(accountId, network);

      return {
        ...this.getInitialAccountData({
          label: label || defaultLabel,
          signer: freshHDSigner,
          sysAccount,
          xprv: encryptedXprv,
        }),
        balances: { syscoin: 0, ethereum: 0 },
      } as IKeyringAccountState;
    } catch (error) {
      console.log('ERROR createUTXOAccountAtIndex', {
        error,
      });
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  }

  private async addNewAccountToSyscoinChain(label?: string) {
    try {
      // Get next available account ID
      const vault = this.getVault();
      const accounts = vault.accounts[KeyringAccountType.HDAccount];
      const nextId = this.getNextAccountId(accounts);

      return await this.createUTXOAccountAtIndex(nextId, label);
    } catch (error) {
      console.log('ERROR addNewAccountToSyscoinChain', {
        error,
      });
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  }

  private async addNewAccountToEth(label?: string) {
    try {
      // Get next available account ID
      const vault = this.getVault();
      const accounts = vault.accounts[KeyringAccountType.HDAccount];
      const nextId = this.getNextAccountId(accounts);

      // EVM accounts should use generic labels since they work across all EVM networks
      const defaultLabel = `Account ${nextId + 1}`;

      const newAccount = await this.setDerivedWeb3Accounts(
        nextId,
        label || defaultLabel,
      );

      return newAccount;
    } catch (error) {
      console.log('ERROR addNewAccountToEth', {
        error,
      });
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  }

  // Helper method to get next available account ID - fills gaps when accounts are deleted
  private getNextAccountId(accounts: any): number {
    const existingIds = Object.values(accounts)
      .filter((account: any) => {
        // Only count accounts that have been properly initialized
        // Placeholder accounts have empty addresses/xprv/xpub
        return account && account.address && account.xpub;
      })
      .map((account: any) => account.id)
      .filter((id) => !isNaN(id))
      .sort((a, b) => a - b); // Sort to find gaps efficiently

    if (existingIds.length === 0) {
      return 0;
    }

    // Find the first gap in the sequence
    for (let i = 0; i < existingIds.length; i++) {
      if (existingIds[i] !== i) {
        // Found a gap at position i
        return i;
      }
    }

    // No gaps found, return next sequential ID
    return existingIds.length;
  }

  private getBasicWeb3AccountInfo = (id: number, label?: string) => {
    return {
      id,
      isTrezorWallet: false,
      isLedgerWallet: false,
      label: label ? label : `Account ${id + 1}`,
    };
  };

  private setDerivedWeb3Accounts = async (
    id: number,
    label: string,
  ): Promise<IKeyringAccountState> => {
    try {
      // For account creation, derive from mnemonic (since account doesn't exist yet)
      const mnemonic = this.getDecryptedMnemonic();
      const hdNode = HDNode.fromMnemonic(mnemonic);
      const derivationPath = getAddressDerivationPath('eth', 60, 0, false, id);
      const derivedAccount = hdNode.derivePath(derivationPath);

      const basicAccountInfo = this.getBasicWeb3AccountInfo(id, label);

      const createdAccount = {
        address: derivedAccount.address,
        xpub: derivedAccount.publicKey,
        xprv: this.withSecureData((sessionPwd) => {
          return CryptoJS.AES.encrypt(
            derivedAccount.privateKey,
            sessionPwd,
          ).toString();
        }),
        isImported: false,
        ...basicAccountInfo,
        balances: { syscoin: 0, ethereum: 0 },
      };

      // NOTE: Account creation should be dispatched to Redux store, not stored here
      // Return the account data for Pali to add to store
      return createdAccount;
    } catch (error) {
      console.log('ERROR setDerivedWeb3Accounts', {
        error,
      });
      this.validateAndHandleErrorByMessage(error.message);
      throw error;
    }
  };

  private setSignerEVM = async (network: INetwork): Promise<void> => {
    const abortController = new AbortController();
    try {
      // With multi-keyring architecture, this is only called on EVM keyrings
      this.ethereumTransaction.setWeb3Provider(network);
      abortController.abort();
    } catch (error) {
      abortController.abort();
      throw new Error(`SetSignerEVM: Failed with ${error}`);
    }
  };

  private clearTemporaryLocalKeys = async (pwd: string) => {
    // Clear the vault completely (set empty mnemonic)
    await setEncryptedVault(
      {
        mnemonic: '',
      },
      pwd,
    );

    // Remove vault-keys from storage so no vault exists at all
    await this.storage.deleteItem('vault-keys');

    console.log('[KeyringManager] Temporary local keys cleared');
    this.logout();
  };

  /**
   * Recreates session data from the encrypted vault.
   *
   * @param password - The raw user password (used to decrypt the vault)
   * @param encryptionKey - The PBKDF2-derived encryption key (NEVER stored, used for session encryption)
   */
  private async recreateSessionFromVault(
    password: string,
    encryptionKey: string,
  ): Promise<void> {
    try {
      const { mnemonic } = await getDecryptedVault(password);

      if (!mnemonic) {
        throw new Error('Mnemonic not found in vault');
      }

      // Store the PBKDF2-derived encryption key (not the hash!)
      // This key is never stored persistently - only in memory during session
      this.sessionPassword = new SecureBuffer(encryptionKey);
      // Encrypt the mnemonic with the derived key for session use
      const encryptedMnemonic = CryptoJS.AES.encrypt(
        mnemonic,
        encryptionKey,
      ).toString();
      this.sessionMnemonic = new SecureBuffer(encryptedMnemonic);
      console.log('[KeyringManager] Session data recreated from vault');
    } catch (error) {
      console.error('ERROR recreateSessionFromVault', { error });
      throw error;
    }
  }

  private async _getPrivateKeyAccountInfos(
    privKey: string,
    label?: string,
    options?: { utxoAddressType?: 'p2wpkh' | 'p2pkh' | 'p2tr' },
  ) {
    const vault = this.getVault();
    const { accounts } = vault;
    let importedAccountValue: {
      address: string;
      privateKey: string;
      publicKey: string;
    } | null = null;

    const balances = {
      syscoin: 0,
      ethereum: 0,
    };

    // Try to validate as extended private key first
    const networkToUse = vault.activeNetwork;
    const zprvValidation = this.validateZprv(privKey, networkToUse);

    // Check if we're on an EVM network (slip44 = 60) or UTXO network
    const isEvmNetwork = networkToUse.slip44 === 60;

    if (zprvValidation.isValid) {
      // This is a valid UTXO extended private key
      if (isEvmNetwork) {
        throw new Error(
          'Cannot import UTXO private key on EVM network. Please switch to a UTXO network (Bitcoin/Syscoin) first.',
        );
      }
      const { node, network } = zprvValidation;

      if (!node || !network) {
        throw new Error('Failed to validate extended private key');
      }

      // Always use index 0 for consistency
      const nodeChild = node.derivePath(`0/0`);
      if (!nodeChild) {
        throw new Error('Failed to derive child node');
      }

      // Choose address type based on options or default to p2wpkh
      let addrObj;
      if (options?.utxoAddressType === 'p2pkh') {
        addrObj = bjs.payments.p2pkh({
          pubkey: nodeChild.publicKey,
          network,
        });
      } else if (options?.utxoAddressType === 'p2tr') {
        // For taproot, use x-only public key (32 bytes instead of 33)
        const xOnly =
          nodeChild.publicKey.length === 33
            ? nodeChild.publicKey.slice(1, 33)
            : nodeChild.publicKey;
        addrObj = bjs.payments.p2tr({
          internalPubkey: xOnly,
          network,
        });
      } else {
        // Default to SegWit (p2wpkh)
        addrObj = bjs.payments.p2wpkh({
          pubkey: nodeChild.publicKey,
          network,
        });
      }

      const { address } = addrObj;
      if (!address) {
        throw new Error('Failed to generate address');
      }

      importedAccountValue = {
        address,
        publicKey: node.neutered().toBase58(),
        privateKey: privKey,
      };

      balances.syscoin = 0;
    } else {
      // If not a valid zprv/vprv, on UTXO networks try WIF
      const isEvmNetwork = networkToUse.slip44 === 60;
      let handledAsUtxo = false;
      if (!isEvmNetwork) {
        const wifValidation = this.validateWif(privKey, networkToUse);
        if (wifValidation.isValid) {
          // Create address from WIF and treat as single-address imported account
          const { networks } = getNetworkConfig(
            networkToUse.slip44,
            networkToUse.currency || 'Bitcoin',
          );
          const isTestnet = networkToUse.slip44 === 1;
          const bitcoinNetwork = isTestnet
            ? networks.testnet
            : networks.mainnet;

          const keyPair = (syscoinjs.utils as any).bitcoinjs.ECPair.fromWIF(
            privKey,
            bitcoinNetwork,
          );
          // Choose address type based on options or default behavior
          let addrObj;
          if (options?.utxoAddressType === 'p2pkh') {
            addrObj = bjs.payments.p2pkh({
              pubkey: keyPair.publicKey,
              network: bitcoinNetwork,
            });
          } else if (options?.utxoAddressType === 'p2tr') {
            // For taproot, use x-only public key (32 bytes instead of 33)
            const xOnly =
              keyPair.publicKey.length === 33
                ? keyPair.publicKey.slice(1, 33)
                : keyPair.publicKey;
            addrObj = bjs.payments.p2tr({
              internalPubkey: xOnly,
              network: bitcoinNetwork,
            });
          } else {
            // Default to SegWit (p2wpkh)
            addrObj = bjs.payments.p2wpkh({
              pubkey: keyPair.publicKey,
              network: bitcoinNetwork,
            });
          }
          const address = addrObj.address;
          if (!address) {
            throw new Error('Failed to generate address from WIF');
          }

          importedAccountValue = {
            address,
            // For single-address WIF accounts, store xpub as the address marker
            publicKey: address,
            privateKey: privKey,
          };

          // Set UTXO balance bucket
          balances.syscoin = 0;
          handledAsUtxo = true;

          // Proceed to account creation below
        } else if (!isEvmNetwork && wifValidation.message) {
          // Provide useful feedback on UTXO network if WIF was attempted and failed
          // Continue to EVM handling only if actually EVM network
        }
      }

      // Check if the validation failed due to network mismatch
      if (
        zprvValidation.message &&
        zprvValidation.message.includes('Network mismatch')
      ) {
        throw new Error(zprvValidation.message);
      }

      // Check if the validation failed due to invalid key prefix (only for known extended key formats)
      if (
        zprvValidation.message &&
        zprvValidation.message.includes('Invalid key prefix')
      ) {
        throw new Error(zprvValidation.message);
      }

      // Check if it failed parsing as an extended key
      if (
        zprvValidation.message &&
        zprvValidation.message.includes('Failed to parse extended private key')
      ) {
        throw new Error(zprvValidation.message);
      }

      // Check if it looks like an extended key that failed validation
      const knownExtendedKeyPrefixes = [
        'xprv',
        'xpub',
        'yprv',
        'ypub',
        'zprv',
        'zpub',
        'tprv',
        'tpub',
        'uprv',
        'upub',
        'vprv',
        'vpub',
      ];
      const prefix = privKey.substring(0, 4);
      const looksLikeExtendedKey = knownExtendedKeyPrefixes.includes(prefix);

      if (looksLikeExtendedKey) {
        // This looks like a UTXO extended key, but it failed validation
        // Don't try to import it as an EVM key
        if (isEvmNetwork) {
          throw new Error(
            'Cannot import UTXO private key on EVM network. Please switch to a UTXO network (Bitcoin/Syscoin) first.',
          );
        }
        // For UTXO networks, throw the original validation error
        throw new Error(
          zprvValidation.message || 'Invalid extended private key',
        );
      }

      // If it's not an extended key and not a valid WIF, treat it as an Ethereum private key
      // But first check if we're on an EVM network
      if (!isEvmNetwork && !handledAsUtxo) {
        throw new Error(
          'Cannot import EVM private key on UTXO network. Please switch to an EVM network first.',
        );
      }

      if (!handledAsUtxo) {
        const hexPrivateKey =
          privKey.slice(0, 2) === '0x' ? privKey : `0x${privKey}`;

        // Validate it's a valid hex string (32 bytes = 64 hex chars)
        if (
          !/^0x[0-9a-fA-F]{64}$/.test(hexPrivateKey) &&
          !/^[0-9a-fA-F]{64}$/.test(privKey)
        ) {
          throw new Error(
            'Invalid private key format. Expected 32-byte hex string or extended private key.',
          );
        }

        importedAccountValue =
          this.ethereumTransaction.importAccount(hexPrivateKey);

        balances.ethereum = 0;
      }
    }

    if (!importedAccountValue) {
      throw new Error(
        'Invalid private key format. Expected WIF, extended private key, or 32-byte hex.',
      );
    }

    const { address, publicKey, privateKey } = importedAccountValue;

    //Validate if account already exists
    const accountAlreadyExists =
      (accounts[KeyringAccountType.Imported] &&
        Object.values(
          accounts[KeyringAccountType.Imported] as IKeyringAccountState[],
        ).some((account) => account.address === address)) ||
      Object.values(
        accounts[KeyringAccountType.HDAccount] as IKeyringAccountState[],
      ).some((account) => account.address === address); //Find a way to verify if private Key is not par of seed wallet derivation path

    if (accountAlreadyExists)
      throw new Error(
        'Account already exists, try again with another Private Key.',
      );

    const id = this.getNextAccountId(accounts[KeyringAccountType.Imported]);
    const defaultLabel: string = label || `Imported ${id + 1}`;
    return {
      ...initialActiveImportedAccountState,
      address,
      label: defaultLabel,
      id,
      balances,
      isImported: true,
      xprv: this.withSecureData((sessionPwd) => {
        return CryptoJS.AES.encrypt(privateKey, sessionPwd).toString();
      }),
      xpub: publicKey,
      assets: {
        syscoin: [],
        ethereum: [],
      },
    } as IKeyringAccountState;
  }

  // NEW: On-demand signer creation methods

  /**
   * Common method to decrypt mnemonic from session
   * Eliminates code duplication across multiple methods
   */
  private getDecryptedMnemonic(): string {
    if (!this.sessionMnemonic || !this.sessionPassword) {
      throw new Error('Session information not available');
    }

    const mnemonic = this.withSecureData((sessionPwd, sessionMnemonic) => {
      const decrypted = CryptoJS.AES.decrypt(
        sessionMnemonic,
        sessionPwd,
      ).toString(CryptoJS.enc.Utf8);

      if (!decrypted) {
        throw new Error('Failed to decrypt mnemonic');
      }

      return decrypted;
    });

    return mnemonic;
  }

  /**
   * Creates network RPC config from current active network without making RPC calls
   * Common utility for all on-demand signer creation
   */
  private createNetworkRpcConfig() {
    const network = this.getVault().activeNetwork;

    return {
      formattedNetwork: network,
      networkConfig: getNetworkConfig(network.slip44, network.currency),
    };
  }

  /**
   * Common signer creation logic - takes decrypted mnemonic/zprv and creates fresh signer
   * OPTIMIZED: No RPC call needed - uses network config directly
   */
  private createFreshUTXOSigner(
    mnemonicOrZprv: string,
    accountId: number,
  ): SyscoinHDSigner {
    // Create signer using network config directly (no RPC call)
    const rpcConfig = this.createNetworkRpcConfig();
    // Type assertion to match getSyscoinSigners expected interface
    const { hd } = getSyscoinSigners({
      mnemonic: mnemonicOrZprv,
      rpc: rpcConfig as any,
    });

    // Create account at the specified index and set it as active
    // Note: createAccountAtIndex is synchronous despite TypeScript types
    hd.createAccountAtIndex(accountId, 84);

    // Verify the account was created correctly
    if (!hd.Signer.accounts.has(accountId)) {
      throw new Error(`Failed to create account at index ${accountId}`);
    }

    // Verify the correct account is active
    if (hd.Signer.accountIndex !== accountId) {
      throw new Error(
        `Account index mismatch: expected ${accountId}, got ${hd.Signer.accountIndex}`,
      );
    }

    return hd;
  }

  /**
   * Creates a fresh UTXO signer for HD accounts derived from the main seed
   * OPTIMIZED: No RPC call needed - uses network config directly
   */
  private createOnDemandUTXOSigner(accountId: number): SyscoinHDSigner {
    // Use common method to avoid code duplication
    const mnemonic = this.getDecryptedMnemonic();
    return this.createFreshUTXOSigner(mnemonic, accountId);
  }

  // NEW: Helper methods for HD signer management
  private isZprv(key: string): boolean {
    const zprvPrefixes = ['zprv', 'tprv', 'vprv', 'xprv'];
    return zprvPrefixes.some((prefix) => key.startsWith(prefix));
  }

  // NEW: Separate session initialization from account creation
  public initializeSession = async (
    seedPhrase: string,
    password: string,
  ): Promise<void> => {
    // Validate inputs first
    if (!BIP84.validateMnemonic(seedPhrase)) {
      throw new Error('Invalid Seed');
    }

    let foundVaultKeys = true;
    let salt = '';
    let encryptionSalt = '';
    const vaultKeys = await this.storage.get('vault-keys');
    if (!vaultKeys || !vaultKeys.salt) {
      foundVaultKeys = false;
      salt = crypto.randomBytes(16).toString('hex');
      // Generate separate salt for encryption key derivation (NEVER used for auth)
      encryptionSalt = crypto.randomBytes(32).toString('hex');
    } else {
      salt = vaultKeys.salt;
      // Use existing encryptionSalt or generate new one for migration
      encryptionSalt =
        vaultKeys.encryptionSalt || crypto.randomBytes(32).toString('hex');
    }

    // Auth hash for password verification using PBKDF2 (secure, can be stored)
    // Uses 120,000 iterations to make brute-force attacks computationally expensive
    const sessionPasswordPbkdf2Hash = this.deriveAuthHash(password, salt);

    // Derive encryption key using PBKDF2 - this is NEVER stored
    const derivedEncryptionKey = this.deriveEncryptionKey(
      password,
      encryptionSalt,
    );

    if (!foundVaultKeys) {
      // Store vault-keys using the storage abstraction
      // Note: encryptionSalt is stored but the derived key is NEVER stored
      await this.storage.set('vault-keys', {
        hash: sessionPasswordPbkdf2Hash, // v3: PBKDF2-based auth hash
        salt,
        encryptionSalt,
        version: 3, // v3 = PBKDF2-based encryption AND auth hash
      });
    } else if (vaultKeys.version < 3) {
      // Existing vault with older version - upgrade to v3 with PBKDF2 auth hash
      await this.storage.set('vault-keys', {
        ...vaultKeys,
        hash: sessionPasswordPbkdf2Hash, // Upgrade to PBKDF2-based auth hash
        encryptionSalt: vaultKeys.encryptionSalt || encryptionSalt,
        version: 3,
      });
    }

    // Check if already initialized with the same password (idempotent behavior)
    if (this.sessionPassword) {
      // Compare derived keys for idempotency check
      if (derivedEncryptionKey === this.getSessionPasswordString()) {
        // Same password - check if it's the same mnemonic to ensure full idempotency
        try {
          const currentMnemonic = this.withSecureData(
            (sessionPwd, sessionMnemonic) => {
              return CryptoJS.AES.decrypt(sessionMnemonic, sessionPwd).toString(
                CryptoJS.enc.Utf8,
              );
            },
          );

          if (currentMnemonic === seedPhrase) {
            // Same mnemonic and password - already initialized
            return;
          }
        } catch (error) {
          // If we can't decrypt, fall through to error
        }
      }

      // Different password or mnemonic - this is not a simple re-initialization
      throw new Error(
        'Wallet already initialized with different parameters. Create a new keyring instance for different parameters.',
      );
    }

    // Encrypt and store vault (mnemonic storage) - now uses single vault for all networks
    await setEncryptedVault(
      {
        mnemonic: seedPhrase, // Store plain mnemonic - setEncryptedVault will encrypt the entire vault
      },
      password,
    );

    // Use PBKDF2-derived key for session encryption
    await this.recreateSessionFromVault(password, derivedEncryptionKey);
  };

  // NEW: Create first account without signer setup
  public createFirstAccount = async (
    label?: string,
  ): Promise<IKeyringAccountState> => {
    if (!this.sessionPassword || !this.sessionMnemonic) {
      throw new Error(
        'Session must be initialized first. Call initializeSession.',
      );
    }

    const vault = this.getVault();
    const network = vault.activeNetwork;

    if (network.kind === INetworkType.Syscoin) {
      // UTXO accounts get network-aware labels since each network has separate keyrings
      const defaultLabel = label || this.generateNetworkAwareLabel(0, network);

      // Create UTXO account using on-demand signer
      const freshHDSigner = this.createOnDemandUTXOSigner(0);

      const sysAccount = await this.getFormattedBackendAccount({
        signer: freshHDSigner,
      });

      const encryptedXprv = this.getEncryptedXprv(freshHDSigner);

      return {
        ...this.getInitialAccountData({
          label: defaultLabel,
          signer: freshHDSigner,
          sysAccount,
          xprv: encryptedXprv,
        }),
        balances: { syscoin: 0, ethereum: 0 },
      } as IKeyringAccountState;
    } else {
      // EVM accounts get generic labels since they work across all EVM networks
      const defaultLabel = label || 'Account 1';
      return await this.setDerivedWeb3Accounts(0, defaultLabel);
    }
  };

  public initializeWalletSecurely = async (
    seedPhrase: string,
    password: string,
  ): Promise<IKeyringAccountState> => {
    // Use new separated approach
    await this.initializeSession(seedPhrase, password);
    return await this.createFirstAccount();
  };

  // Helper methods for secure buffer operations
  private getSessionPasswordString(): string {
    if (!this.sessionPassword || this.sessionPassword.isCleared()) {
      throw new Error('Session password not available');
    }
    // WARNING: This exposes sensitive data as a string
    // Use only for CryptoJS operations that require string input
    return this.sessionPassword.toString();
  }

  private getSessionMnemonicString(): string {
    if (!this.sessionMnemonic || this.sessionMnemonic.isCleared()) {
      throw new Error('Session mnemonic not available');
    }
    // WARNING: This exposes sensitive data as a string
    // Use only for CryptoJS operations that require string input
    return this.sessionMnemonic.toString();
  }

  // Secure method to perform cryptographic operations without exposing strings
  private withSecureData<T>(
    operation: (password: string, mnemonic: string) => T,
  ): T {
    if (!this.sessionPassword || !this.sessionMnemonic) {
      throw new Error('Session data not available');
    }

    // Perform operation with minimal exposure
    const result = operation(
      this.getSessionPasswordString(),
      this.getSessionMnemonicString(),
    );

    // Clear any temporary variables if needed
    return result;
  }

  /**
   * Gets the legacy session password (hash-based key) for migration purposes.
   * Only available during v1->v2 migration.
   */
  private getLegacySessionPasswordString(): string | null {
    if (!this.legacySessionPassword || this.legacySessionPassword.isCleared()) {
      return null;
    }
    return this.legacySessionPassword.toString();
  }

  /**
   * Checks if we're currently in a migration state with legacy keys available.
   */
  public isInMigrationState(): boolean {
    return (
      this.legacySessionPassword !== null &&
      !this.legacySessionPassword.isCleared()
    );
  }

  /**
   * Decrypts an xprv value, trying the new PBKDF2-derived key first,
   * then falling back to the legacy hash-based key during migration.
   *
   * @param encryptedXprv - The encrypted xprv string
   * @returns The decrypted xprv string
   */
  public decryptXprvWithFallback(encryptedXprv: string): string {
    if (!this.sessionPassword) {
      throw new Error('Session not available');
    }

    // Try new PBKDF2-derived key first
    try {
      const decrypted = CryptoJS.AES.decrypt(
        encryptedXprv,
        this.getSessionPasswordString(),
      ).toString(CryptoJS.enc.Utf8);

      if (decrypted && decrypted.length > 0) {
        return decrypted;
      }
    } catch (e) {
      // Fall through to try legacy key
    }

    // If new key failed and we have legacy key, try that
    const legacyKey = this.getLegacySessionPasswordString();
    if (legacyKey) {
      try {
        const decrypted = CryptoJS.AES.decrypt(
          encryptedXprv,
          legacyKey,
        ).toString(CryptoJS.enc.Utf8);

        if (decrypted && decrypted.length > 0) {
          console.log(
            '[KeyringManager] Decrypted xprv using legacy key (migration needed)',
          );
          return decrypted;
        }
      } catch (e) {
        throw new Error(
          'Failed to decrypt xprv with both new and legacy keys',
        );
      }
    }

    throw new Error('Failed to decrypt xprv - invalid key or corrupted data');
  }

  /**
   * Migrates an encrypted xprv from the legacy format to the new PBKDF2-based format.
   * Call this for each account's xprv after unlock when needsXprvMigration is true.
   *
   * @param encryptedXprv - The xprv encrypted with the old hash-based key
   * @returns The xprv encrypted with the new PBKDF2-derived key
   */
  public migrateXprv(encryptedXprv: string): string {
    // Decrypt with fallback (will use legacy key if needed)
    const decryptedXprv = this.decryptXprvWithFallback(encryptedXprv);

    // Re-encrypt with new PBKDF2-derived key
    const reEncrypted = CryptoJS.AES.encrypt(
      decryptedXprv,
      this.getSessionPasswordString(),
    ).toString();

    return reEncrypted;
  }

  /**
   * Clears the legacy session password after migration is complete.
   * Call this after all accounts have been migrated.
   */
  public clearLegacySession(): void {
    if (this.legacySessionPassword) {
      this.legacySessionPassword.clear();
      this.legacySessionPassword = null;
      console.log('[KeyringManager] Legacy session cleared after migration');
    }
  }

  private generateNetworkAwareLabel(
    accountId: number,
    network: INetwork,
  ): string {
    // Generate concise network-specific labels using actual network config
    const { label, chainId, kind, currency } = network;

    // Create a shortened network identifier based on actual network configurations
    let networkPrefix = '';

    if (kind === INetworkType.Syscoin) {
      // UTXO networks (slip44 = 57 for mainnet, 1 for testnet)
      if (chainId === 57) {
        networkPrefix = 'SYS'; // Syscoin UTXO Mainnet
      } else if (chainId === 5700) {
        networkPrefix = 'SYS-T'; // Syscoin UTXO Testnet (slip44=1)
      } else {
        // Other UTXO networks - use currency shortcut (e.g., "btc" -> "BTC")
        if (currency) {
          networkPrefix = currency.toUpperCase();
        } else {
          // Fallback to first word from label if no currency
          const firstWord = label.split(' ')[0];
          networkPrefix =
            firstWord.length > 6 ? firstWord.substring(0, 6) : firstWord;
        }
      }
    } else {
      // EVM networks (all use slip44=60)
      if (chainId === 1) {
        networkPrefix = 'ETH'; // Ethereum Mainnet
      } else if (chainId === 11155111) {
        networkPrefix = 'ETH-T'; // Ethereum Sepolia Testnet
      } else if (chainId === 137) {
        networkPrefix = 'POLY'; // Polygon Mainnet
      } else if (chainId === 80001) {
        networkPrefix = 'POLY-T'; // Polygon Mumbai Testnet
      } else if (chainId === 57) {
        networkPrefix = 'NEVM'; // Syscoin NEVM Mainnet
      } else if (chainId === 5700) {
        networkPrefix = 'NEVM-T'; // Syscoin NEVM Testnet
      } else if (chainId === 570) {
        networkPrefix = 'ROLLUX'; // Rollux Mainnet
      } else if (chainId === 57000) {
        networkPrefix = 'ROLLUX-T'; // Rollux Testnet
      } else {
        // Other EVM networks - use currency shortcut if available
        if (currency) {
          // Check if it's a testnet network
          if (
            label.toLowerCase().includes('testnet') ||
            label.toLowerCase().includes('test')
          ) {
            networkPrefix = `${currency.toUpperCase()}-T`;
          } else {
            networkPrefix = currency.toUpperCase();
          }
        } else {
          // Fallback to extracting meaningful prefix from label
          const firstWord = label.split(' ')[0];
          if (
            firstWord.toLowerCase().includes('testnet') ||
            firstWord.toLowerCase().includes('test')
          ) {
            const baseWord = label.split(' ')[0];
            networkPrefix = `${baseWord.substring(0, 4).toUpperCase()}-T`;
          } else {
            networkPrefix =
              firstWord.length > 6
                ? firstWord.substring(0, 6).toUpperCase()
                : firstWord.toUpperCase();
          }
        }
      }
    }

    return `${networkPrefix} ${accountId + 1}`;
  }

  /**
   * Clean up all resources
   */
  public async destroy(): Promise<void> {
    await this.lockWallet();

    // Clear any remaining references
    this.ethereumTransaction = {} as EthereumTransactions;
    this.syscoinTransaction = {} as SyscoinTransactions;
  }
}
