/* eslint-disable camelcase */
/* eslint-disable import/no-named-as-default */
/* eslint-disable import/order */
import Transport from '@ledgerhq/hw-transport';
import SysUtxoClient, { WalletPolicy } from './bitcoin_client';
import type { Psbt } from 'bitcoinjs-lib';
import {
  RECEIVING_ADDRESS_INDEX,
  DESCRIPTOR,
  WILL_NOT_DISPLAY,
} from './consts';
import { getNetworkConfig } from '@sidhujag/sysweb3-network';
import BIP32Factory from 'bip32';
import ecc from '@bitcoinerlab/secp256k1';
import { IEvmMethods, IUTXOMethods, MessageTypes } from './types';
import LedgerEthClient, { ledgerService } from '@ledgerhq/hw-app-eth';
import { Transaction } from 'syscoinjs-lib';
import {
  TypedDataUtils,
  TypedMessage,
  SignTypedDataVersion,
  TypedDataV1,
} from '@metamask/eth-sig-util';
import {
  getAccountDerivationPath,
  getAddressDerivationPath,
  isEvmCoin,
} from '../utils/derivation-paths';

import {
  HardwareWalletManager,
  HardwareWalletType,
} from '../hardware-wallet-manager';
//

export class LedgerKeyring {
  public ledgerEVMClient!: LedgerEthClient;
  public ledgerUtxoClient!: SysUtxoClient;
  private hdPath = "m/44'/57'/0'/0/0";
  public evm: IEvmMethods;
  public utxo: IUTXOMethods;
  public transport: Transport | null = null;
  private hardwareWalletManager: HardwareWalletManager;
  // In-memory cache of registered wallet policy HMACs
  private walletHmacCache: Map<string, Buffer> = new Map();

  /**
   * @param sharedHardwareWalletManager Optional shared HardwareWalletManager instance.
   *                                     If provided, this will be used instead of creating
   *                                     a new instance. This allows multiple KeyringManagers
   *                                     to share the same Ledger connection.
   */
  constructor(sharedHardwareWalletManager?: HardwareWalletManager) {
    this.hardwareWalletManager =
      sharedHardwareWalletManager || new HardwareWalletManager();

    // Set up event listeners
    this.hardwareWalletManager.on('connected', ({ type }) => {
      if (type === HardwareWalletType.LEDGER) {
        console.log('Ledger connected');
      }
    });

    this.hardwareWalletManager.on('disconnected', ({ type }) => {
      if (type === HardwareWalletType.LEDGER) {
        console.log('Ledger disconnected');
        this.transport = null;
        // Clear clients on disconnect
        this.ledgerEVMClient = null as any;
        this.ledgerUtxoClient = null as any;
        this.walletHmacCache.clear();
      }
    });

    this.hardwareWalletManager.on('connectionFailed', ({ type, error }) => {
      if (type === HardwareWalletType.LEDGER) {
        console.error('Ledger connection failed:', error);
      }
    });

    this.evm = {
      getEvmAddressAndPubKey: this.getEvmAddressAndPubKey,
      signEVMTransaction: this.signEVMTransaction,
      signPersonalMessage: this.signPersonalMessage,
      signTypedData: this.signTypedData,
    };

    this.utxo = {
      getUtxoAddress: this.getUtxoAddress,
      getXpub: this.getXpub,
      verifyUtxoAddress: this.verifyUtxoAddress,
    };
  }

  /**
   * Ensure Ledger is connected with automatic retry
   * Note: This is automatically called by all operations through executeWithRetry
   * External callers don't need to call this directly
   */
  public async ensureConnection(): Promise<void> {
    await this.hardwareWalletManager.ensureConnection(
      HardwareWalletType.LEDGER
    );
    this.transport = await this.hardwareWalletManager.getLedgerConnection();

    // Create clients if transport is available
    if (this.transport && (!this.ledgerEVMClient || !this.ledgerUtxoClient)) {
      this.ledgerEVMClient = new LedgerEthClient(this.transport);
      this.ledgerUtxoClient = new SysUtxoClient(this.transport);
    }
  }

  private getUtxoAddress = async ({
    coin,
    index, // account index
    slip44,
    showInLedger,
  }: {
    coin: string;
    index: number;
    showInLedger?: boolean;
    slip44: number;
  }) => {
    return this.executeWithRetry(async () => {
      const fingerprint = await this.ledgerUtxoClient.getMasterFingerprint();
      const xpub = await this.getXpub({ index, coin, slip44 });
      this.setHdPath(coin, index, slip44);

      // xpub/tpub already comes from device; no conversion needed here
      const xpubWithDescriptor = `[${this.hdPath}]${xpub}`.replace(
        'm',
        fingerprint
      );
      const walletPolicy = new WalletPolicy(coin, DESCRIPTOR, [
        xpubWithDescriptor,
      ]);
      const hmac = await this.getOrRegisterHmac(walletPolicy, fingerprint);

      const address = await this.ledgerUtxoClient.getWalletAddress(
        walletPolicy,
        hmac,
        RECEIVING_ADDRESS_INDEX,
        0, // verify imported account address at first receive index
        !!showInLedger
      );

      return address;
    }, 'getUtxoAddress');
  };

  public verifyUtxoAddress = async (
    accountIndex: number,
    currency: string,
    slip44: number
  ) =>
    await this.getUtxoAddress({
      coin: currency,
      index: accountIndex,
      slip44: slip44,
      showInLedger: true,
    });

  private getXpub = async ({
    index,
    coin,
    slip44,
  }: {
    coin: string;
    index: number;
    slip44: number;
  }): Promise<string> => {
    return this.executeWithRetry(async () => {
      this.setHdPath(coin, index, slip44);

      {
        // Try silent first, then fall back to on-device display for unusual paths
        try {
          return await this.ledgerUtxoClient.getExtendedPubkey(
            this.hdPath,
            WILL_NOT_DISPLAY
          );
        } catch (err) {
          // Retry with display=true to allow unusual paths with user approval
          return await this.ledgerUtxoClient.getExtendedPubkey(
            this.hdPath,
            true
          );
        }
      }
    }, 'getXpub');
  };

  /**
   * Sign a UTXO message - public method used by transaction classes
   */
  public signUtxoMessage = async (path: string, message: string) => {
    return this.executeWithRetry(async () => {
      const bufferMessage = Buffer.from(message);
      const signature = await this.ledgerUtxoClient.signMessage(
        bufferMessage,
        path
      );
      return signature;
    }, 'signUtxoMessage');
  };

  private signEVMTransaction = async ({
    rawTx,
    accountIndex,
  }: {
    accountIndex: number;
    rawTx: string;
  }) => {
    return this.executeWithRetry(async () => {
      this.setHdPath('eth', accountIndex, 60);
      const resolution = await ledgerService.resolveTransaction(rawTx, {}, {});

      const signature = await this.ledgerEVMClient.signTransaction(
        this.hdPath.replace(/^m\//, ''), // Remove 'm/' prefix for EVM
        rawTx,
        resolution
      );

      return signature;
    }, 'signEVMTransaction');
  };

  private signPersonalMessage = async ({
    message,
    accountIndex,
  }: {
    accountIndex: number;
    message: string;
  }) => {
    return this.executeWithRetry(async () => {
      this.setHdPath('eth', accountIndex, 60);

      const signature = await this.ledgerEVMClient.signPersonalMessage(
        this.hdPath.replace(/^m\//, ''), // Remove 'm/' prefix for EVM
        message
      );

      return `0x${signature.r}${signature.s}${signature.v.toString(16)}`;
    }, 'signPersonalMessage');
  };

  private sanitizeData(data: any): any {
    switch (Object.prototype.toString.call(data)) {
      case '[object Object]': {
        const entries = Object.keys(data).map((k) => [
          k,
          this.sanitizeData(data[k]),
        ]);
        return Object.fromEntries(entries);
      }

      case '[object Array]':
        return data.map((v: any[]) => this.sanitizeData(v));

      case '[object BigInt]':
        return data.toString();

      default:
        return data;
    }
  }

  private transformTypedData = <T extends MessageTypes>(
    data: TypedMessage<T>,
    version: SignTypedDataVersion
  ) => {
    const { types, primaryType, domain, message } = this.sanitizeData(data);

    const domainSeparatorHash = TypedDataUtils.hashStruct(
      'EIP712Domain',
      this.sanitizeData(domain),
      types,
      version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
    ).toString('hex');

    let messageHash: string | null = null;

    if (primaryType !== 'EIP712Domain') {
      messageHash = TypedDataUtils.hashStruct(
        primaryType as string,
        this.sanitizeData(message),
        types,
        version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
      ).toString('hex');
    }

    return {
      domain_separator_hash: domainSeparatorHash,
      message_hash: messageHash,
      ...data,
    };
  };

  private getEvmAddressAndPubKey = async ({
    accountIndex,
  }: {
    accountIndex: number;
  }): Promise<{ address: string; publicKey: string }> => {
    return this.executeWithRetry(async () => {
      this.setHdPath('eth', accountIndex, 60);
      const { address, publicKey } = await this.ledgerEVMClient.getAddress(
        this.hdPath.replace(/^m\//, '') // Remove 'm/' prefix for EVM
      );
      return { address, publicKey };
    }, 'getEvmAddressAndPubKey');
  };

  private signTypedData = async ({
    version,
    data,
    accountIndex,
  }: {
    accountIndex: number;
    data: TypedMessage<any> | TypedDataV1;
    version: SignTypedDataVersion;
  }) => {
    return this.executeWithRetry(async () => {
      this.setHdPath('eth', accountIndex, 60);

      // V1 typed data is not supported by hardware wallets
      if (version === SignTypedDataVersion.V1) {
        throw new Error(
          'Ledger: V1 typed data signing is not supported. Please use V3 or V4.'
        );
      }

      const dataWithHashes = this.transformTypedData(
        data as TypedMessage<any>,
        version
      );

      const { domain_separator_hash, message_hash } = dataWithHashes;

      const signature = await this.ledgerEVMClient.signEIP712HashedMessage(
        this.hdPath.replace(/^m\//, ''), // Remove 'm/' prefix for EVM
        domain_separator_hash,
        message_hash ? message_hash : ''
      );

      return `0x${signature.r}${signature.s}${signature.v.toString(16)}`;
    }, 'signTypedData');
  };

  private getMasterFingerprint = async () => {
    try {
      const masterFingerprint =
        await this.ledgerUtxoClient.getMasterFingerprint();
      return masterFingerprint;
    } catch (error) {
      console.log('Fingerprint error: ', error);
      throw error;
    }
  };

  // Build a stable cache key for a policy bound to the device and derivation path
  private buildWalletCacheKey(
    fingerprint: string,
    walletPolicy: WalletPolicy
  ): string {
    // Wallet HMACs are bound to a specific wallet policy id.
    // The id commits to: version, wallet name, descriptor template hash, and the merkle root of keys.
    // Therefore, caching by (fingerprint + walletId) avoids collisions across different networks
    // that may share the same derivation path (e.g., multiple slip44=1 testnets).
    return `${fingerprint}|${walletPolicy.getId().toString('hex')}`;
  }

  // Lazily register the wallet policy and cache HMAC in memory only
  private async getOrRegisterHmac(
    walletPolicy: any,
    fingerprint: string
  ): Promise<Buffer | null> {
    const cacheKey = this.buildWalletCacheKey(fingerprint, walletPolicy);

    const cached = this.walletHmacCache.get(cacheKey);
    if (cached) return cached;

    // If registerWallet is unavailable (tests/mocks), fall back to null HMAC
    const registerWallet: any = (this.ledgerUtxoClient as any)?.registerWallet;
    if (typeof registerWallet !== 'function') {
      return null;
    }

    try {
      // Register once (device approval). If user cancels, error will propagate via retryOperation
      const result = await registerWallet.call(
        this.ledgerUtxoClient,
        walletPolicy
      );
      const walletHMAC = Array.isArray(result) ? result[1] : null;
      if (walletHMAC && Buffer.isBuffer(walletHMAC)) {
        this.walletHmacCache.set(cacheKey, walletHMAC);
        return walletHMAC;
      }
      return null;
    } catch (e) {
      // On failure, proceed without HMAC (device may prompt)
      return null;
    }
  }

  private setHdPath(coin: string, accountIndex: number, slip44: number) {
    if (isEvmCoin(coin, slip44)) {
      // For EVM, the "accountIndex" parameter is actually used as the address index
      // EVM typically uses account 0, and different addresses are at different address indices
      this.hdPath = getAddressDerivationPath(
        coin,
        slip44,
        0, // account is always 0 for EVM
        false, // not a change address
        accountIndex // this is actually the address index for EVM
      );
    } else {
      // For UTXO, use account-level derivation path
      this.hdPath = getAccountDerivationPath(coin, slip44, accountIndex);
    }
  }
  /**
   * Convert PSBT to Ledger format with retry logic
   */
  public async convertToLedgerFormat(
    psbt: Psbt,
    accountXpub: string,
    accountId: number,
    currency: string,
    slip44: number
  ): Promise<Psbt> {
    return this.executeWithRetry(async () => {
      // Ensure Ledger is connected before attempting operations
      // This is now handled by executeWithRetry

      // Build a bitcoinjs-bip32 network from slip44/currency so zpub/vpub parse directly
      const { networks, types } = getNetworkConfig(slip44, currency);
      const isTestnet = slip44 === 1;
      const pubTypes = isTestnet
        ? (types.zPubType as any).testnet
        : types.zPubType.mainnet;
      const baseNetwork = isTestnet ? networks.testnet : networks.mainnet;
      const network = {
        ...baseNetwork,
        bip32: {
          public: parseInt(pubTypes.vpub || pubTypes.zpub, 16),
          private: parseInt(pubTypes.vprv || pubTypes.zprv, 16),
        },
      } as any;

      const bip32 = BIP32Factory(ecc as any);
      const accountNode = bip32.fromBase58(accountXpub, network);

      // Get master fingerprint
      const fingerprint = await this.getMasterFingerprint();

      // Enhance each input with bip32Derivation
      const missingInputDerivations: number[] = [];
      for (let i = 0; i < psbt.inputCount; i++) {
        const dataInput = psbt.data.inputs[i];

        // Skip if already has bip32Derivation
        if (dataInput.bip32Derivation && dataInput.bip32Derivation.length > 0) {
          continue;
        }

        // Ensure witnessUtxo is present if nonWitnessUtxo exists
        if (!dataInput.witnessUtxo && dataInput.nonWitnessUtxo) {
          const txBuffer = dataInput.nonWitnessUtxo;
          const tx = Transaction.fromBuffer(txBuffer);
          const vout = psbt.txInputs[i].index;

          if (tx.outs[vout]) {
            dataInput.witnessUtxo = {
              script: tx.outs[vout].script,
              value: tx.outs[vout].value,
            };
          }
        }

        // Extract path from unknownKeyVals by searching for the key, not using hardcoded index
        let pathFromInput: string | null = null;
        if (dataInput.unknownKeyVals && dataInput.unknownKeyVals.length > 0) {
          for (const kv of dataInput.unknownKeyVals) {
            const keyStr = Buffer.from(kv.key).toString();
            if (keyStr === 'path') {
              pathFromInput = Buffer.from(kv.value).toString();
              break;
            }
          }
        }
        let bip32Derivation: any = null;
        if (pathFromInput) {
          const fullPath = pathFromInput;
          const accountPath = getAccountDerivationPath(
            currency,
            slip44,
            accountId
          );
          const relativePath = fullPath
            .replace(accountPath, '')
            .replace(/^\//, '');
          const derivationTokens = relativePath.split('/').filter((t) => t);

          const derivedAccount = derivationTokens.reduce(
            (acc: any, token: string) => {
              const index = parseInt(token);
              if (isNaN(index)) {
                return acc;
              }
              return acc.derive(index);
            },
            accountNode
          );

          const rawPubkey = derivedAccount.publicKey;
          const pubkeyBuf = Buffer.isBuffer(rawPubkey)
            ? rawPubkey
            : Buffer.from(rawPubkey);

          if (pubkeyBuf && pubkeyBuf.length === 33) {
            // Add the bip32Derivation that Ledger needs
            bip32Derivation = {
              masterFingerprint: Buffer.from(fingerprint, 'hex'),
              path: fullPath,
              pubkey: pubkeyBuf,
            };

            psbt.updateInput(i, {
              bip32Derivation: [bip32Derivation],
            });
          }
        }
        // Check the updated PSBT state (avoid stale local references)
        const updatedInput = psbt.data.inputs[i];
        if (
          !updatedInput.bip32Derivation ||
          updatedInput.bip32Derivation.length === 0
        ) {
          missingInputDerivations.push(i);
        }
      }

      // Enhance each output with bip32Derivation when it's a change/output owned by the wallet
      for (let i = 0; i < psbt.data.outputs.length; i++) {
        const dataOutput = psbt.data.outputs[i];

        // Skip if derivation already present
        if (
          dataOutput.bip32Derivation &&
          dataOutput.bip32Derivation.length > 0
        ) {
          continue;
        }

        // Extract path from unknownKeyVals by searching for the key 'path'
        let pathFromOutput: string | null = null;
        if (dataOutput.unknownKeyVals && dataOutput.unknownKeyVals.length > 0) {
          for (const kv of dataOutput.unknownKeyVals) {
            const keyStr = Buffer.from(kv.key).toString();
            if (keyStr === 'path') {
              pathFromOutput = Buffer.from(kv.value).toString();
              break;
            }
          }
        }
        if (pathFromOutput) {
          let bip32Derivation: any = null;
          const fullPath = pathFromOutput;
          const accountPath = getAccountDerivationPath(
            currency,
            slip44,
            accountId
          );
          const relativePath = fullPath
            .replace(accountPath, '')
            .replace(/^\//, '');
          const derivationTokens = relativePath.split('/').filter((t) => t);

          const derivedAccount = derivationTokens.reduce(
            (acc: any, token: string) => {
              const index = parseInt(token);
              if (isNaN(index)) {
                return acc;
              }
              return acc.derive(index);
            },
            accountNode
          );

          const rawOutPubkey = derivedAccount.publicKey;
          const outPubkeyBuf = Buffer.isBuffer(rawOutPubkey)
            ? rawOutPubkey
            : Buffer.from(rawOutPubkey);

          if (outPubkeyBuf && outPubkeyBuf.length === 33) {
            bip32Derivation = {
              masterFingerprint: Buffer.from(fingerprint, 'hex'),
              path: fullPath,
              pubkey: outPubkeyBuf,
            };

            psbt.updateOutput(i, {
              bip32Derivation: [bip32Derivation],
            });
          }
          // Outputs without valid derivation are allowed (external recipients)
        }
      }

      // If any wallet-owned inputs/outputs are missing bip32Derivation, fail early with a clear error
      if (missingInputDerivations.length > 0) {
        const parts: string[] = [];
        parts.push(`inputs [${missingInputDerivations.join(', ')}]`);
        throw new Error(
          `convertToLedgerFormat: Missing bip32Derivation for ${parts.join(
            ' and '
          )}. Ensure PSBT includes a 'path' unknownKeyVal or BIP32_DERIVATION for wallet-owned entries.`
        );
      }

      return psbt;
    }, 'convertToLedgerFormat');
  }

  /**
   * Execute operation with automatic retry
   */
  private async executeWithRetry<T>(
    operation: () => Promise<T>,
    operationName: string
  ): Promise<T> {
    // Ensure connection first
    await this.ensureConnection();

    // Use hardware wallet manager's retry mechanism
    return this.hardwareWalletManager.retryOperation(operation, operationName, {
      maxRetries: 3,
      baseDelay: 1000,
      maxDelay: 5000,
      backoffMultiplier: 2,
    });
  }

  /**
   * Get hardware wallet status
   */
  public getStatus() {
    return this.hardwareWalletManager
      .getStatus()
      .find((s) => s.type === HardwareWalletType.LEDGER);
  }

  /**
   * Clean up resources
   */
  public async destroy() {
    await this.hardwareWalletManager.destroy();
    this.transport = null;
  }
}
