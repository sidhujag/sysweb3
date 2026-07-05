import {
  decrypt,
  signTypedData as signTypedDataUtil,
  TypedMessage,
  SignTypedDataVersion,
  TypedDataV1,
  getEncryptionPublicKey,
  recoverPersonalSignature,
  recoverTypedSignature,
  EthEncryptedData,
} from '@metamask/eth-sig-util';
import { INetwork, INetworkType } from '@sidhujag/sysweb3-network';
import {
  createContractUsingAbi,
  getErc20Abi,
  getErc21Abi,
  getErc55Abi,
} from '@sidhujag/sysweb3-utils';
import { EthereumTransactionEIP1559 } from '@trezor/connect-web';
import omit from 'lodash/omit';

import {
  BigNumber,
  Contract,
  Deferrable,
  TransactionRequest,
  TransactionResponse,
  Zero,
  formatEther,
  formatUnits,
  isHexString,
  normalizeTxValue,
  parseUnits,
  resolveProperties,
  serializeTransaction,
} from '../ethers-v6';
import { LedgerKeyring } from '../ledger';
import { CustomJsonRpcProvider } from '../providers';
import { TrezorKeyring } from '../trezor';
import {
  IResponseFromSendErcSignedTransaction,
  ISendSignedErcTransactionProps,
  IEthereumTransactions,
  SimpleTransactionRequest,
  KeyringAccountType,
  accountType,
  IGasParams,
} from '../types';
import {
  deriveEvmAccountFromMnemonic,
  parsePersonalMessage as parseLocalPersonalMessage,
  privateKeyToAccount,
  sendLocalEvmTransaction,
  signDigestHex,
  signPersonalMessage as signLocalPersonalMessage,
} from './evm-local-signer';
import { getAddressDerivationPath } from '../utils/derivation-paths';

const stripHexPrefix = (value: string) =>
  value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;

const normalizeEthersOverrideValue = (value: any) => normalizeTxValue(value);

const normalizeEthersOverrides = (overrides: Record<string, any>) => {
  const normalized = { ...overrides };
  for (const field of [
    'gasLimit',
    'gasPrice',
    'maxFeePerGas',
    'maxPriorityFeePerGas',
  ]) {
    if (normalized[field] != null) {
      normalized[field] = normalizeEthersOverrideValue(normalized[field]);
    }
  }
  return normalized;
};

export class EthereumTransactions implements IEthereumTransactions {
  private _web3Provider: CustomJsonRpcProvider;
  private _web3ProviderKey?: string;
  public trezorSigner: TrezorKeyring;
  public ledgerSigner: LedgerKeyring;
  private getNetwork: () => INetwork;
  private abortController: AbortController;
  private getDecryptedPrivateKey: () => {
    address: string;
    decryptedPrivateKey: string;
  };

  // Allow manual override of gas parameters when automatic estimation fails
  private gasOverrides: {
    minGasLimit?: BigNumber;
    minPriorityFee?: BigNumber;
    feeMultiplier?: number;
  } = {};

  private getState: () => {
    accounts: {
      HDAccount: accountType;
      Imported: accountType;
      Ledger: accountType;
      Trezor: accountType;
    };
    activeAccountId: number;
    activeAccountType: KeyringAccountType;
    activeNetwork: INetwork;
  };

  constructor(
    getNetwork: () => INetwork,
    getDecryptedPrivateKey: () => {
      address: string;
      decryptedPrivateKey: string;
    },
    getState: () => {
      accounts: {
        HDAccount: accountType;
        Imported: accountType;
        Ledger: accountType;
        Trezor: accountType;
      };
      activeAccountId: number;
      activeAccountType: KeyringAccountType;
      activeNetwork: INetwork;
    },
    ledgerSigner: LedgerKeyring,
    trezorSigner: TrezorKeyring
  ) {
    this.getNetwork = getNetwork;
    this.getDecryptedPrivateKey = getDecryptedPrivateKey;
    this.abortController = new AbortController();

    // NOTE: Defer network access until vault state getter is initialized
    // The web3Provider will be created lazily when first accessed via getters

    this.getState = getState;
    this.trezorSigner = trezorSigner;
    this.ledgerSigner = ledgerSigner;
  }

  // Getter that automatically ensures providers are initialized when accessed
  public get web3Provider(): CustomJsonRpcProvider {
    this.ensureProvidersInitialized();
    return this._web3Provider;
  }

  // Helper method to ensure providers are initialized when first needed
  private ensureProvidersInitialized() {
    // Keep provider in sync with current network selection.
    // Hardware-wallet signing (e.g., Trezor) commits to a chainId; if the provider points at a different
    // RPC/network than `activeNetwork`, nodes will reject broadcasts with chain-id mismatch errors.
    try {
      const currentNetwork = this.getNetwork();
      const currentUrl = currentNetwork?.url;
      const currentKey = `${currentNetwork?.chainId ?? 'unknown'}|${
        currentUrl ?? ''
      }`;
      const needsInit =
        !this._web3Provider ||
        !this._web3ProviderKey ||
        (currentUrl && this._web3ProviderKey !== currentKey);
      if (needsInit) {
        this.setWeb3Provider(currentNetwork);
      }
    } catch (error: any) {
      // If vault state not available yet, providers will be initialized later
      // when setWeb3Provider is called explicitly
      console.log(
        '[EthereumTransactions] Deferring provider initialization:',
        error?.message || error
      );
    }
  }

  // Helper method to detect UTXO networks
  private isUtxoNetwork(network: INetwork): boolean {
    // Generic UTXO network detection patterns:
    // 1. URL contains blockbook or trezor (most reliable)
    // 2. Network kind is explicitly set to 'syscoin'
    const hasBlockbookUrl = !!(
      network.url?.includes('blockbook') || network.url?.includes('trezor')
    );
    const hasUtxoKind = (network as any).kind === INetworkType.Syscoin;

    return hasBlockbookUrl || hasUtxoKind;
  }

  signTypedData = async (
    addr: string,
    typedData: TypedDataV1 | TypedMessage<any>,
    version: SignTypedDataVersion
  ) => {
    const { address, decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { activeAccountType, accounts, activeAccountId } = this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    // Validate that the derived address matches the active account to prevent race conditions
    if (address.toLowerCase() !== activeAccount.address.toLowerCase()) {
      throw {
        message: `Account state mismatch detected. Expected ${activeAccount.address} but got ${address}. Please try again after account switching completes.`,
      };
    }

    const signTypedDataLocal = () => {
      if (addr.toLowerCase() !== address.toLowerCase())
        throw {
          message: 'Decrypting for wrong address, change activeAccount maybe',
        };

      const privKey = Buffer.from(stripHexPrefix(decryptedPrivateKey), 'hex');
      return signTypedDataUtil({
        privateKey: privKey,
        data: typedData as any,
        version,
      });
    };

    const signTypedDataWithLedger = async () => {
      if (addr.toLowerCase() !== activeAccount.address.toLowerCase())
        throw {
          message: 'Decrypting for wrong address, change activeAccount maybe',
        };
      return await this.ledgerSigner.evm.signTypedData({
        version,
        accountIndex: activeAccountId,
        data: typedData,
      });
    };

    const signTypedDataWithTrezor = async () => {
      if (addr.toLowerCase() !== activeAccount.address.toLowerCase())
        throw {
          message: 'Decrypting for wrong address, change activeAccount maybe',
        };
      return await this.trezorSigner.signTypedData({
        version,
        address: addr,
        data: typedData,
        index: activeAccountId,
      });
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await signTypedDataWithTrezor();
      case KeyringAccountType.Ledger:
        return await signTypedDataWithLedger();
      default:
        return signTypedDataLocal();
    }
  };

  // Verify a UTXO address on the connected hardware wallet (Ledger or Trezor)
  // Routes to the appropriate device based on activeAccountType
  verifyUtxoAddress = async (
    accountIndex: number,
    currency: string,
    slip44: number
  ): Promise<string | undefined> => {
    const { activeAccountType } = this.getState();

    switch (activeAccountType) {
      case KeyringAccountType.Ledger:
        return await this.ledgerSigner.verifyUtxoAddress(
          accountIndex,
          currency,
          slip44
        );
      case KeyringAccountType.Trezor:
        return await this.trezorSigner.verifyUtxoAddress(
          accountIndex,
          currency,
          slip44
        );
      default:
        throw new Error(
          'verifyUtxoAddress is only available for hardware wallet accounts'
        );
    }
  };

  verifyTypedSignature = (
    data: TypedDataV1 | TypedMessage<any>,
    signature: string,
    version: SignTypedDataVersion
  ) => {
    try {
      return recoverTypedSignature({ data: data as any, signature, version });
    } catch (error) {
      throw error;
    }
  };

  ethSign = async (params: string[]) => {
    const { address, decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { accounts, activeAccountId, activeAccountType, activeNetwork } =
      this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    // Validate that the derived address matches the active account to prevent race conditions
    if (address.toLowerCase() !== activeAccount.address.toLowerCase()) {
      throw {
        message: `Account state mismatch detected. Expected ${activeAccount.address} but got ${address}. Please try again after account switching completes.`,
      };
    }

    let msg = '';
    //Comparisions do not need to care for checksum address
    if (params[0].toLowerCase() === address.toLowerCase()) {
      msg = stripHexPrefix(params[1]);
    } else if (params[1].toLowerCase() === address.toLowerCase()) {
      msg = stripHexPrefix(params[0]);
    } else {
      throw new Error('Signing for wrong address');
    }

    const sign = () => {
      try {
        // Validate and prepare the message for eth_sign
        let msgHash: Buffer;

        // Check if message is a valid 32-byte hex string
        if (msg.length === 64 && /^[0-9a-fA-F]+$/.test(msg)) {
          // Message is already a 32-byte hex string
          msgHash = Buffer.from(msg, 'hex');
        } else {
          // Message is not a proper hash - provide helpful error
          throw new Error(
            `Expected message to be an Uint8Array with length 32. ` +
              `Got message of length ${msg.length}: "${msg.substring(0, 50)}${
                msg.length > 50 ? '...' : ''
              }". ` +
              `For signing arbitrary text, use personal_sign instead of eth_sign.`
          );
        }

        return signDigestHex(msgHash, decryptedPrivateKey);
      } catch (error) {
        throw error;
      }
    };

    const signWithLedger = async () => {
      try {
        const response = await this.ledgerSigner.evm.signPersonalMessage({
          accountIndex: activeAccountId,
          message: msg,
        });
        return response;
      } catch (error) {
        throw error;
      }
    };

    const signWithTrezor = async () => {
      try {
        // For EVM networks, Trezor expects 'eth' regardless of the network's currency
        const trezorCoin =
          activeNetwork.slip44 === 60 ? 'eth' : activeNetwork.currency;
        const response: any = await this.trezorSigner.signMessage({
          coin: trezorCoin,
          address: activeAccount.address,
          index: activeAccountId,
          message: msg,
          slip44: activeNetwork.slip44,
        });
        return response.signature as string;
      } catch (error) {
        throw error;
      }
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await signWithTrezor();
      case KeyringAccountType.Ledger:
        return await signWithLedger();
      default:
        return sign();
    }
  };

  signPersonalMessage = async (params: string[]) => {
    const { address, decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { accounts, activeAccountId, activeAccountType, activeNetwork } =
      this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    // Validate that the derived address matches the active account to prevent race conditions
    if (address.toLowerCase() !== activeAccount.address.toLowerCase()) {
      throw {
        message: `Account state mismatch detected. Expected ${activeAccount.address} but got ${address}. Please try again after account switching completes.`,
      };
    }

    let msg = '';

    if (params[0].toLowerCase() === address.toLowerCase()) {
      msg = params[1];
    } else if (params[1].toLowerCase() === address.toLowerCase()) {
      msg = params[0];
    } else {
      throw new Error('Signing for wrong address');
    }

    const signPersonalMessageWithDefaultWallet = () => {
      try {
        // Handle both hex-encoded and plain text messages for personal_sign
        let message: Buffer;
        if (msg.startsWith('0x')) {
          const rawHex = stripHexPrefix(msg);
          if (rawHex.length % 2 === 0 && isHexString(msg)) {
            // Message is valid hex-encoded bytes.
            message = Buffer.from(rawHex, 'hex');
          } else {
            // Malformed 0x-prefixed strings are literal text, not lossy hex.
            message = Buffer.from(msg, 'utf8');
          }
        } else {
          // Message is plain text
          message = Buffer.from(msg, 'utf8');
        }

        return signLocalPersonalMessage(message, decryptedPrivateKey);
      } catch (error) {
        throw error;
      }
    };

    const signPersonalMessageWithLedger = async () => {
      try {
        // Handle both hex-encoded and plain text messages for personal_sign
        let messageForLedger: string;
        if (msg.startsWith('0x')) {
          // Message is hex-encoded, remove 0x prefix
          messageForLedger = msg.replace('0x', '');
        } else {
          // Message is plain text, convert to hex
          messageForLedger = Buffer.from(msg, 'utf8').toString('hex');
        }

        const response = await this.ledgerSigner.evm.signPersonalMessage({
          accountIndex: activeAccountId,
          message: messageForLedger,
        });
        return response;
      } catch (error) {
        throw error;
      }
    };

    const signPersonalMessageWithTrezor = async () => {
      try {
        // Handle both hex-encoded and plain text messages for personal_sign
        let messageForTrezor: string;
        if (msg.startsWith('0x')) {
          // Message is hex-encoded, keep as is
          messageForTrezor = msg;
        } else {
          // Message is plain text, convert to hex with 0x prefix
          messageForTrezor = '0x' + Buffer.from(msg, 'utf8').toString('hex');
        }

        // For EVM networks, Trezor expects 'eth' regardless of the network's currency
        const trezorCoin =
          activeNetwork.slip44 === 60 ? 'eth' : activeNetwork.currency;
        const response: any = await this.trezorSigner.signMessage({
          coin: trezorCoin,
          address: activeAccount.address,
          index: activeAccountId,
          message: messageForTrezor,
          slip44: activeNetwork.slip44,
        });
        return response.signature as string;
      } catch (error) {
        throw error;
      }
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await signPersonalMessageWithTrezor();
      case KeyringAccountType.Ledger:
        return await signPersonalMessageWithLedger();
      default:
        return signPersonalMessageWithDefaultWallet();
    }
  };

  parsePersonalMessage = (hexMsg: string) => {
    try {
      return parseLocalPersonalMessage(hexMsg);
    } catch (error) {
      throw error;
    }
  };

  verifyPersonalMessage = (message: string, sign: string) => {
    try {
      const msgParams = {
        data: message,
        signature: sign,
      };
      return recoverPersonalSignature(msgParams as any);
    } catch (error) {
      throw error;
    }
  };

  getEncryptedPubKey = () => {
    const { activeAccountType } = this.getState();

    // Hardware wallets don't support encryption public key generation
    if (
      activeAccountType === KeyringAccountType.Trezor ||
      activeAccountType === KeyringAccountType.Ledger
    ) {
      throw new Error(
        'Hardware wallets do not support eth_getEncryptionPublicKey'
      );
    }

    const { decryptedPrivateKey } = this.getDecryptedPrivateKey();

    try {
      return getEncryptionPublicKey(stripHexPrefix(decryptedPrivateKey));
    } catch (error) {
      throw error;
    }
  };

  // eth_decryptMessage
  decryptMessage = (msgParams: string[]) => {
    const { activeAccountType } = this.getState();

    // Hardware wallets don't support message decryption
    if (
      activeAccountType === KeyringAccountType.Trezor ||
      activeAccountType === KeyringAccountType.Ledger
    ) {
      throw new Error('Hardware wallets do not support eth_decrypt');
    }

    const { address, decryptedPrivateKey } = this.getDecryptedPrivateKey();

    let encryptedData = '';

    if (msgParams[0].toLowerCase() === address.toLowerCase()) {
      encryptedData = msgParams[1];
    } else if (msgParams[1].toLowerCase() === address.toLowerCase()) {
      encryptedData = msgParams[0];
    } else {
      throw new Error('Decrypting for wrong receiver');
    }
    encryptedData = stripHexPrefix(encryptedData);

    try {
      const buff = Buffer.from(encryptedData, 'hex');
      const cleanData: EthEncryptedData = JSON.parse(buff.toString('utf8'));
      const sig = decrypt({
        encryptedData: cleanData,
        privateKey: stripHexPrefix(decryptedPrivateKey),
      });
      return sig;
    } catch (error) {
      throw error;
    }
  };

  toBigNumber = (aBigNumberish: string | number) =>
    BigNumber.from(String(aBigNumberish));

  private toHex0x = (value: any, fieldName: string): string => {
    if (value === undefined || value === null) return '0x0';
    if (typeof value === 'string') {
      const v = value.trim();
      if (v === '') return '0x0';
      if (v.startsWith('0x')) return v;
      return BigNumber.from(v).toHexString();
    }
    if (typeof value === 'number') return BigNumber.from(value).toHexString();
    if (BigNumber.isBigNumber(value)) return value.toHexString();
    const maybeHex = (value as any)?._hex ?? (value as any)?.hex ?? value;
    try {
      return BigNumber.from(maybeHex).toHexString();
    } catch (_e) {
      throw new Error(
        `Invalid numeric field "${fieldName}" for EVM tx: ${String(value)}`
      );
    }
  };

  private resolveEvmFeeParams = async ({
    gasPrice,
    isLegacy = false,
    maxFeePerGas,
    maxPriorityFeePerGas,
  }: {
    gasPrice?: any;
    isLegacy?: boolean;
    maxFeePerGas?: any;
    maxPriorityFeePerGas?: any;
  }) => {
    if (isLegacy) {
      return {
        gasPrice: gasPrice || (await this.web3Provider.getGasPrice()),
        isLegacy: true,
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
      };
    }

    if (!maxFeePerGas || maxPriorityFeePerGas == null) {
      const feeData = await this.web3Provider.getFeeData();
      maxFeePerGas = maxFeePerGas || feeData.maxFeePerGas || feeData.gasPrice;
      maxPriorityFeePerGas =
        maxPriorityFeePerGas ?? feeData.maxPriorityFeePerGas;

      if (!maxFeePerGas || maxPriorityFeePerGas == null) {
        return {
          gasPrice: feeData.gasPrice || (await this.web3Provider.getGasPrice()),
          isLegacy: true,
          maxFeePerGas: undefined,
          maxPriorityFeePerGas: undefined,
        };
      }
    }

    return {
      gasPrice: undefined,
      isLegacy: false,
      maxFeePerGas,
      maxPriorityFeePerGas,
    };
  };

  getData = ({
    contractAddress,
    receivingAddress,
    value,
  }: {
    contractAddress: string;
    receivingAddress: string;
    value: any;
  }) => {
    const abi = getErc20Abi() as any;
    try {
      const contract = createContractUsingAbi(
        abi,
        contractAddress,
        this.web3Provider
      );
      const data = contract.interface.encodeFunctionData('transfer', [
        receivingAddress,
        value,
      ]);

      return data;
    } catch (error) {
      throw error;
    }
  };

  getFeeDataWithDynamicMaxPriorityFeePerGas = async () => {
    let maxFeePerGas = this.toBigNumber(0);
    let maxPriorityFeePerGas = this.toBigNumber(0);

    try {
      // First, try to get the current gas price as a baseline
      const currentGasPrice = await this.web3Provider.getGasPrice();

      const block = await this.web3Provider.getBlock('latest');
      if (block && block.baseFeePerGas != null) {
        const baseFeePerGas = BigNumber.from(block.baseFeePerGas);
        try {
          // Some networks don't support this RPC method
          const ethMaxPriorityFee = await this.web3Provider.send(
            'eth_maxPriorityFeePerGas',
            []
          );
          maxPriorityFeePerGas = BigNumber.from(ethMaxPriorityFee);

          // Apply minimum priority fee override if set
          if (
            this.gasOverrides.minPriorityFee &&
            maxPriorityFeePerGas.lt(this.gasOverrides.minPriorityFee)
          ) {
            maxPriorityFeePerGas = this.gasOverrides.minPriorityFee;
          }

          if (maxPriorityFeePerGas.isZero()) {
            throw new Error('Max priority fee is zero');
          }

          // For networks with validation issues, use current gas price as baseline
          // This ensures we're not setting fees that the network will reject
          const baselineMaxFee = currentGasPrice.mul(120).div(100); // 20% above current gas price

          // Calculate standard maxFeePerGas
          const multiplier = this.gasOverrides.feeMultiplier || 250;
          const calculatedMaxFee = baseFeePerGas
            .mul(multiplier)
            .div(100)
            .add(maxPriorityFeePerGas);

          // Use the higher of the two to ensure transaction goes through
          maxFeePerGas = calculatedMaxFee.gt(baselineMaxFee)
            ? calculatedMaxFee
            : baselineMaxFee;
        } catch (e) {
          // Use a more aggressive fallback strategy with higher priority fees
          // Check if we can get fee history for better estimation
          try {
            const feeHistory = await this.web3Provider.send('eth_feeHistory', [
              '0x5', // Last 5 blocks
              'latest',
              [25, 50, 75], // Percentiles for priority fees
            ]);

            if (
              feeHistory &&
              feeHistory.reward &&
              feeHistory.reward.length > 0
            ) {
              // Use median of the 50th percentile from recent blocks
              const recentFees = feeHistory.reward
                .map((r: any[]) => r[1]) // Get 50th percentile
                .filter((f: any) => f && f !== '0x0')
                .map((f: any) => BigNumber.from(f));

              if (recentFees.length > 0) {
                // Use the median value with a 50% buffer for better reliability
                const sortedFees = recentFees.sort((a, b) =>
                  a.sub(b).isNegative() ? -1 : 1
                );
                const medianFee = sortedFees[Math.floor(sortedFees.length / 2)];
                maxPriorityFeePerGas = medianFee.mul(150).div(100); // Add 50% buffer
              } else {
                // Fallback with higher default (5 gwei for better validation)
                maxPriorityFeePerGas = BigNumber.from('5000000000');
              }
            } else {
              // Fallback with higher default (5 gwei for better validation)
              maxPriorityFeePerGas = BigNumber.from('5000000000');
            }
          } catch (feeHistoryError) {
            // If fee history fails, use current gas price as reference
            console.warn(
              'Fee history not available, using gas price based estimation'
            );
            // Use 10% of current gas price as priority fee
            const currentGasPrice = await this.web3Provider.getGasPrice();
            maxPriorityFeePerGas = currentGasPrice.mul(10).div(100);

            // Ensure minimum of 1 gwei
            const minPriority = BigNumber.from('1000000000');
            if (maxPriorityFeePerGas.lt(minPriority)) {
              maxPriorityFeePerGas = minPriority;
            }
          }

          // Calculate maxFeePerGas based on current network conditions
          const currentGasPrice = await this.web3Provider.getGasPrice();
          const baselineMaxFee = currentGasPrice.mul(120).div(100);
          const calculatedMaxFee = baseFeePerGas
            .mul(250)
            .div(100)
            .add(maxPriorityFeePerGas);
          maxFeePerGas = calculatedMaxFee.gt(baselineMaxFee)
            ? calculatedMaxFee
            : baselineMaxFee;
        }

        // Ensure maxFeePerGas is at least 20% higher than maxPriorityFeePerGas
        const minMaxFee = maxPriorityFeePerGas.mul(120).div(100);
        if (maxFeePerGas.lt(minMaxFee)) {
          maxFeePerGas = minMaxFee;
        }

        return { maxFeePerGas, maxPriorityFeePerGas };
      } else if (block && block.baseFeePerGas == null) {
        // For non-EIP1559 chains, return zeros to indicate legacy transaction should be used
        console.log('Chain does not support EIP1559, use legacy transactions');
        return {
          maxFeePerGas: BigNumber.from(0),
          maxPriorityFeePerGas: BigNumber.from(0),
        };
      } else if (!block) throw new Error('Block not found');

      return { maxFeePerGas, maxPriorityFeePerGas };
    } catch (error) {
      console.error(error);
      return { maxFeePerGas, maxPriorityFeePerGas };
    }
  };
  calculateNewGasValues = (
    oldTxsParams: IGasParams,
    isForCancel: boolean,
    isLegacy: boolean
  ): IGasParams => {
    const newGasValues: IGasParams = {
      maxFeePerGas: undefined,
      maxPriorityFeePerGas: undefined,
      gasPrice: undefined,
      gasLimit: undefined,
    };

    const { maxFeePerGas, maxPriorityFeePerGas, gasLimit, gasPrice } =
      oldTxsParams;

    const calculateAndConvertNewValue = (feeValue: number) => {
      // Apply multiplier for replacement transaction (cancel or speedup)
      const newValue = feeValue * multiplierToUse;

      const calculateValue = String(newValue);

      const convertValueToHex =
        '0x' + parseInt(calculateValue, 10).toString(16);

      return BigNumber.from(convertValueToHex);
    };

    const maxFeePerGasToNumber = maxFeePerGas?.toNumber();
    const maxPriorityFeePerGasToNumber = maxPriorityFeePerGas?.toNumber();
    const gasLimitToNumber = gasLimit?.toNumber();
    const gasPriceToNumber = gasPrice?.toNumber();

    const multiplierToUse = 1.2; //The same calculation we used in the edit fee modal, always using the 0.2 multiplier

    if (!isLegacy) {
      // For EIP-1559 transactions
      newGasValues.maxFeePerGas = calculateAndConvertNewValue(
        maxFeePerGasToNumber as number
      );
      newGasValues.maxPriorityFeePerGas = calculateAndConvertNewValue(
        maxPriorityFeePerGasToNumber as number
      );
    }

    if (isLegacy) {
      newGasValues.gasPrice = calculateAndConvertNewValue(
        gasPriceToNumber as number
      );
    }

    if (isForCancel) {
      const DEFAULT_GAS_LIMIT_VALUE = '42000';

      const convertToHex =
        '0x' + parseInt(DEFAULT_GAS_LIMIT_VALUE, 10).toString(16);

      newGasValues.gasLimit = BigNumber.from(convertToHex);
    }

    if (!isForCancel) {
      newGasValues.gasLimit = calculateAndConvertNewValue(
        gasLimitToNumber as number
      );
    }

    return newGasValues;
  };
  cancelSentTransaction = async (
    txHash: string,
    isLegacy?: boolean,
    fallbackNonce?: number
  ): Promise<{
    error?: boolean;
    isCanceled: boolean;
    transaction?: TransactionResponse;
  }> => {
    const { activeAccountType, activeAccountId, accounts, activeNetwork } =
      this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    let tx = (await this.web3Provider.getTransaction(
      txHash
    )) as Deferrable<TransactionResponse>;

    // If transaction not found, create a minimal tx object with current gas prices
    // This handles cases where tx with 0 gas never made it to the mempool
    if (!tx && fallbackNonce !== undefined) {
      // Fetch current network gas prices for the cancellation
      if (isLegacy) {
        const currentGasPrice = await this.web3Provider.getGasPrice();
        tx = {
          from: activeAccount.address,
          to: activeAccount.address,
          value: Zero,
          nonce: fallbackNonce,
          gasPrice: currentGasPrice,
          gasLimit: BigNumber.from(42000),
          data: '0x',
        } as any;
      } else {
        const feeData = await this.getFeeDataWithDynamicMaxPriorityFeePerGas();
        tx = {
          from: activeAccount.address,
          to: activeAccount.address,
          value: Zero,
          nonce: fallbackNonce,
          maxFeePerGas: BigNumber.from(feeData.maxFeePerGas || 0),
          maxPriorityFeePerGas: BigNumber.from(
            feeData.maxPriorityFeePerGas || 0
          ),
          gasLimit: BigNumber.from(42000),
          data: '0x',
        } as any;
      }
    } else if (!tx) {
      // No fallback nonce provided and tx not found
      return {
        isCanceled: false,
        error: true,
      };
    }

    // If the original tx has 0 or very low gas price, fetch current network gas prices
    const oldTxsGasValues: IGasParams = {
      maxFeePerGas: tx.maxFeePerGas as BigNumber,
      maxPriorityFeePerGas: tx.maxPriorityFeePerGas as BigNumber,
      gasPrice: tx.gasPrice as BigNumber,
      gasLimit: tx.gasLimit as BigNumber,
    };

    // Only fetch current gas prices if the original tx has exactly 0 or undefined gas
    // This avoids unnecessary backend calls for legitimate low-gas networks (L2s, testnets)
    if (isLegacy) {
      if (!oldTxsGasValues.gasPrice || oldTxsGasValues.gasPrice.isZero()) {
        // Fetch current network gas price for replacement
        const currentGasPrice = await this.web3Provider.getGasPrice();
        oldTxsGasValues.gasPrice = currentGasPrice;
      }
    } else {
      // For EIP-1559 transactions
      if (
        !oldTxsGasValues.maxFeePerGas ||
        oldTxsGasValues.maxFeePerGas.isZero()
      ) {
        // Fetch current network fee data for replacement
        const feeData = await this.getFeeDataWithDynamicMaxPriorityFeePerGas();
        oldTxsGasValues.maxFeePerGas = BigNumber.from(
          feeData.maxFeePerGas || 0
        );
        oldTxsGasValues.maxPriorityFeePerGas = BigNumber.from(
          feeData.maxPriorityFeePerGas || 0
        );
      }
    }

    const newGasValues = this.calculateNewGasValues(
      oldTxsGasValues,
      true,
      isLegacy || false
    );

    // Base cancel transaction parameters (same for all wallet types)
    const baseCancelTx = {
      nonce: tx.nonce,
      from: activeAccount.address,
      to: activeAccount.address,
      value: Zero,
      gasLimit: newGasValues.gasLimit,
    };

    const changedTxToCancel: Deferrable<TransactionRequest> = isLegacy
      ? {
          ...baseCancelTx,
          gasPrice: newGasValues.gasPrice,
          type: 0, // Force Type 0 for legacy cancel
        }
      : {
          ...baseCancelTx,
          maxFeePerGas: newGasValues.maxFeePerGas,
          maxPriorityFeePerGas: newGasValues.maxPriorityFeePerGas,
          // Don't set type - let ethers auto-detect
        };

    // Ledger cancel handler
    const cancelWithLedger = async () => {
      try {
        const resolvedParams = await resolveProperties(
          omit(changedTxToCancel, 'from')
        );
        const formatParams = {
          ...resolvedParams,
          nonce: resolvedParams.nonce
            ? Number(resolvedParams.nonce.toString())
            : undefined,
        };
        const txFormattedForEthers = isLegacy
          ? {
              ...formatParams,
              chainId: activeNetwork.chainId,
              type: 0, // Need explicit type for hardware wallet serialization
            }
          : {
              ...formatParams,
              chainId: activeNetwork.chainId,
              type: 2, // Need explicit type for hardware wallet serialization
            };

        const rawTx = serializeTransaction(txFormattedForEthers);
        const signature = await this.ledgerSigner.evm.signEVMTransaction({
          rawTx: rawTx.replace('0x', ''),
          accountIndex: activeAccountId,
        });

        const formattedSignature = {
          r: `0x${signature.r}`,
          s: `0x${signature.s}`,
          v: parseInt(signature.v, 16),
        };

        if (signature) {
          const signedTx = serializeTransaction(
            txFormattedForEthers,
            formattedSignature
          );
          const transactionResponse = await this.web3Provider.sendTransaction(
            signedTx
          );

          return {
            isCanceled: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isCanceled: false,
            error: true,
          };
        }
      } catch (error) {
        return {
          isCanceled: false,
          error: true,
        };
      }
    };

    // Trezor cancel handler
    const cancelWithTrezor = async () => {
      try {
        const trezorCoin =
          activeNetwork.slip44 === 60 ? 'eth' : activeNetwork.currency;
        const formattedTx = await resolveProperties(
          omit(changedTxToCancel, 'from')
        );

        const txFormattedForTrezor: any = {
          ...formattedTx,
          gasLimit:
            typeof formattedTx.gasLimit === 'string'
              ? formattedTx.gasLimit
              : this.toHex0x(formattedTx.gasLimit, 'gasLimit'),
          value: '0x0',
          nonce: this.toHex0x(formattedTx.nonce, 'nonce'),
          chainId: activeNetwork.chainId,
          type: isLegacy ? 0 : 2, // Need explicit type for hardware wallet serialization
        };

        if (isLegacy) {
          txFormattedForTrezor.gasPrice =
            typeof formattedTx.gasPrice === 'string'
              ? formattedTx.gasPrice
              : this.toHex0x(formattedTx.gasPrice, 'gasPrice');
        } else {
          txFormattedForTrezor.maxFeePerGas =
            typeof (formattedTx as any).maxFeePerGas === 'string'
              ? (formattedTx as any).maxFeePerGas
              : this.toHex0x((formattedTx as any).maxFeePerGas, 'maxFeePerGas');
          txFormattedForTrezor.maxPriorityFeePerGas =
            typeof (formattedTx as any).maxPriorityFeePerGas === 'string'
              ? (formattedTx as any).maxPriorityFeePerGas
              : this.toHex0x(
                  (formattedTx as any).maxPriorityFeePerGas,
                  'maxPriorityFeePerGas'
                );
        }

        const signature = await this.trezorSigner.signEthTransaction({
          coin: trezorCoin,
          tx: txFormattedForTrezor,
          index: activeAccountId.toString(),
          slip44: activeNetwork.slip44,
        });

        if (signature.success) {
          const signedTx = serializeTransaction(
            txFormattedForTrezor,
            signature.payload
          );
          const transactionResponse = await this.web3Provider.sendTransaction(
            signedTx
          );

          return {
            isCanceled: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isCanceled: false,
            error: true,
          };
        }
      } catch (error) {
        return {
          isCanceled: false,
          error: true,
        };
      }
    };

    // Regular wallet cancel handler
    const cancelWithPrivateKey = async () => {
      try {
        const { decryptedPrivateKey } = this.getDecryptedPrivateKey();
        const transactionResponse = await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          changedTxToCancel
        );

        if (transactionResponse) {
          return {
            isCanceled: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isCanceled: false,
          };
        }
      } catch (error) {
        return {
          isCanceled: false,
          error: true,
        };
      }
    };

    // Route based on account type
    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await cancelWithTrezor();
      case KeyringAccountType.Ledger:
        return await cancelWithLedger();
      default:
        return await cancelWithPrivateKey();
    }
  };
  //TODO: This function needs to be refactored
  sendFormattedTransaction = async (
    params: SimpleTransactionRequest,
    isLegacy?: boolean
  ) => {
    const { activeAccountType, activeAccountId, accounts, activeNetwork } =
      this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    // Check if we should force legacy transactions for networks with EIP-1559 issues
    // Some networks have issues with EIP-1559 validation
    if (!isLegacy && params.maxFeePerGas && params.maxPriorityFeePerGas) {
      const maxFee = BigNumber.from(params.maxFeePerGas);
      const priorityFee = BigNumber.from(params.maxPriorityFeePerGas);

      // If fees are zero or network doesn't support EIP-1559, use legacy
      if (maxFee.isZero() || priorityFee.isZero()) {
        console.log('Switching to legacy transaction due to zero fees');
        isLegacy = true;

        // Convert to legacy by using gasPrice
        const gasPrice = await this.web3Provider.getGasPrice();
        params.gasPrice = gasPrice.mul(110).div(100); // 10% buffer
        // @ts-ignore
        delete params.maxFeePerGas;

        // @ts-ignore
        delete params.maxPriorityFeePerGas;
      }
    }

    // Only apply a minimum gas limit when a network-specific override is set.
    // Otherwise keep the user/dapp-approved gas limit unchanged.
    if (params.gasLimit && this.gasOverrides.minGasLimit) {
      const minGasLimit = this.gasOverrides.minGasLimit;
      const currentGasLimit = BigNumber.from(params.gasLimit);
      if (currentGasLimit.lt(minGasLimit)) {
        params.gasLimit = minGasLimit;
      }
    }

    const txForEstimation = {
      ...params,
      from: params.from || activeAccount.address,
    };
    if (!params.gasLimit) {
      params.gasLimit = await this.web3Provider.estimateGas(txForEstimation);
    }
    if (isLegacy) {
      if (!params.gasPrice) {
        params.gasPrice = await this.web3Provider.getGasPrice();
      }
    } else if (!params.maxFeePerGas || !params.maxPriorityFeePerGas) {
      const feeData = await this.web3Provider.getFeeData();
      params.maxFeePerGas =
        params.maxFeePerGas || feeData.maxFeePerGas || feeData.gasPrice;
      params.maxPriorityFeePerGas =
        params.maxPriorityFeePerGas || feeData.maxPriorityFeePerGas;
      if (!params.maxFeePerGas || !params.maxPriorityFeePerGas) {
        isLegacy = true;
        params.gasPrice =
          feeData.gasPrice || (await this.web3Provider.getGasPrice());
        delete (params as any).maxFeePerGas;
        delete (params as any).maxPriorityFeePerGas;
      }
    }

    const sendEVMLedgerTransaction = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccount.address
      );
      const formatParams = isLegacy
        ? omit(params, 'from')
        : omit(params, ['from', 'gasPrice']); // Strip gasPrice for EIP-1559
      const txFormattedForEthers = isLegacy
        ? {
            ...formatParams,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 0, // Force Type 0 for legacy
          }
        : {
            ...formatParams,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 2, // Need explicit type for hardware wallet serialization
          };
      const rawTx = serializeTransaction(txFormattedForEthers);

      const signature = await this.ledgerSigner.evm.signEVMTransaction({
        rawTx: rawTx.replace('0x', ''),
        accountIndex: activeAccountId,
      });

      const formattedSignature = {
        r: `0x${signature.r}`,
        s: `0x${signature.s}`,
        v: parseInt(signature.v, 16),
      };

      if (signature) {
        try {
          const signedTx = serializeTransaction(
            txFormattedForEthers,
            formattedSignature
          );
          const finalTx = await this.web3Provider.sendTransaction(signedTx);

          return finalTx;
        } catch (error) {
          throw error;
        }
      } else {
        throw new Error(`Transaction Signature Failed. Error: ${signature}`);
      }
    };

    const sendEVMTrezorTransaction = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccount.address
      );
      let txFormattedForTrezor = {};
      const formatParams = isLegacy
        ? omit(params, 'from')
        : omit(params, ['from', 'gasPrice']); // Strip gasPrice for EIP-1559
      switch (isLegacy) {
        case true:
          txFormattedForTrezor = {
            ...formatParams,
            gasLimit: this.toHex0x(
              (formatParams as any).gasLimit ?? (params as any).gasLimit,
              'gasLimit'
            ),
            value: this.toHex0x(
              (formatParams as any).value ?? (params as any).value,
              'value'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: (formatParams as any).data ?? '0x',
          };
          break;
        case false:
          txFormattedForTrezor = {
            ...formatParams,
            gasLimit: this.toHex0x(
              (formatParams as any).gasLimit ?? (params as any).gasLimit,
              'gasLimit'
            ),
            maxFeePerGas: this.toHex0x(
              (formatParams as any).maxFeePerGas ??
                (params as any).maxFeePerGas,
              'maxFeePerGas'
            ),
            maxPriorityFeePerGas: this.toHex0x(
              (formatParams as any).maxPriorityFeePerGas ??
                (params as any).maxPriorityFeePerGas,
              'maxPriorityFeePerGas'
            ),
            value: this.toHex0x(
              (formatParams as any).value ?? (params as any).value,
              'value'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: (formatParams as any).data ?? '0x',
          };
          break;
        default:
          txFormattedForTrezor = {
            ...formatParams,
            gasLimit: this.toHex0x(
              (formatParams as any).gasLimit ?? (params as any).gasLimit,
              'gasLimit'
            ),
            maxFeePerGas: this.toHex0x(
              (formatParams as any).maxFeePerGas ??
                (params as any).maxFeePerGas,
              'maxFeePerGas'
            ),
            maxPriorityFeePerGas: this.toHex0x(
              (formatParams as any).maxPriorityFeePerGas ??
                (params as any).maxPriorityFeePerGas,
              'maxPriorityFeePerGas'
            ),
            value: this.toHex0x(
              (formatParams as any).value ?? (params as any).value,
              'value'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: (formatParams as any).data ?? '0x',
          };
          break;
      }

      const signature = await this.trezorSigner.signEthTransaction({
        index: `${activeAccountId}`,
        tx: txFormattedForTrezor as EthereumTransactionEIP1559,
        coin: activeNetwork.currency,
        slip44: activeNetwork.slip44,
      });
      if (signature.success) {
        try {
          const txFormattedForEthers = isLegacy
            ? {
                ...formatParams,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 0, // Force Type 0 for legacy
              }
            : {
                ...formatParams,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 2, // Need explicit type for hardware wallet serialization
              };
          signature.payload.v = parseInt(signature.payload.v, 16); //v parameter must be a number by ethers standards
          const signedTx = serializeTransaction(
            txFormattedForEthers,
            signature.payload
          );
          const finalTx = await this.web3Provider.sendTransaction(signedTx);

          return finalTx;
        } catch (error) {
          throw error;
        }
      } else {
        throw new Error(`Transaction Signature Failed. Error: ${signature}`);
      }
    };

    const sendEVMTransaction = async () => {
      const { address, decryptedPrivateKey } = this.getDecryptedPrivateKey();

      // Validate that we have the correct private key for the active account to prevent race conditions
      // This is critical for transaction security during account switches
      if (address.toLowerCase() !== activeAccount.address.toLowerCase()) {
        throw new Error(
          `Account state mismatch detected during transaction. Expected ${activeAccount.address} but got ${address}. Please wait for account switching to complete and try again.`
        );
      }

      // Explicitly set transaction type based on isLegacy flag
      // For EIP-1559, ensure gasPrice is not present to avoid ethers throwing
      const tx: Deferrable<TransactionRequest> = isLegacy
        ? { ...params, type: 0 } // Force Type 0 for legacy transactions
        : (omit(params, ['gasPrice']) as Deferrable<TransactionRequest>); // Strip gasPrice for EIP-1559

      try {
        const transaction = await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          tx
        );
        const response = await this.web3Provider.getTransaction(
          transaction.hash
        );
        //TODO: more precisely on this lines
        if (!response) {
          return await this.getTransactionTimestamp(transaction);
        } else {
          return await this.getTransactionTimestamp(response);
        }
      } catch (error) {
        throw error;
      }
    };
    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await sendEVMTrezorTransaction();
      case KeyringAccountType.Ledger:
        return await sendEVMLedgerTransaction();
      default:
        return await sendEVMTransaction();
    }
  };
  sendTransactionWithEditedFee = async (
    txHash: string,
    isLegacy?: boolean
  ): Promise<{
    error?: boolean;
    isSpeedUp: boolean;
    transaction?: TransactionResponse;
  }> => {
    let tx = (await this.web3Provider.getTransaction(
      txHash
    )) as Deferrable<TransactionResponse>;

    if (!tx) {
      // Retry a couple of times in case the node hasn't indexed the pending tx yet
      for (let attempt = 0; attempt < 2 && !tx; attempt++) {
        await new Promise((resolve) =>
          setTimeout(resolve, 500 * (attempt + 1))
        );
        tx = (await this.web3Provider.getTransaction(
          txHash
        )) as Deferrable<TransactionResponse>;
      }
      if (!tx) {
        return {
          isSpeedUp: false,
          error: true,
          code: 'TX_NOT_FOUND',
          message: 'Original transaction not yet available from RPC provider',
        } as any;
      }
    }

    const { activeAccountType, activeAccountId, accounts, activeNetwork } =
      this.getState();
    const activeAccount = accounts[activeAccountType][activeAccountId];

    // Check if this might be a max send transaction by comparing total cost to balance
    const currentBalance = await this.web3Provider.getBalance(
      activeAccount.address
    );

    // Ensure all transaction values are resolved from promises
    const gasLimit = await Promise.resolve(tx.gasLimit);
    const gasPrice = await Promise.resolve(tx.gasPrice || 0);
    const maxFeePerGas = await Promise.resolve(tx.maxFeePerGas || 0);
    const maxPriorityFeePerGas = await Promise.resolve(
      tx.maxPriorityFeePerGas || 0
    );
    const txValue = await Promise.resolve(tx.value);
    const txData = await Promise.resolve(tx.data || '0x');

    // Check if this is a contract call (has data)
    const isContractCall = txData && txData !== '0x' && txData.length > 2;

    const originalGasCost = isLegacy
      ? gasLimit.mul(gasPrice || 0)
      : gasLimit.mul(maxFeePerGas || 0);
    const originalTotalCost = txValue.add(originalGasCost);

    // If original transaction used >95% of balance, it's likely a max send
    const balanceThreshold = currentBalance.mul(95).div(100);
    const isLikelyMaxSend = originalTotalCost.gt(balanceThreshold);

    let txWithEditedFee: Deferrable<TransactionRequest>;

    // If the original tx has 0 or very low gas price, fetch current network gas prices
    const oldTxsGasValues: IGasParams = {
      maxFeePerGas: maxFeePerGas as BigNumber,
      maxPriorityFeePerGas: maxPriorityFeePerGas as BigNumber,
      gasPrice: gasPrice as BigNumber,
      gasLimit: gasLimit as BigNumber,
    };

    // Only fetch current gas prices if the original tx has exactly 0 or undefined gas
    // This avoids unnecessary backend calls for legitimate low-gas networks (L2s, testnets)
    if (isLegacy) {
      if (!oldTxsGasValues.gasPrice || oldTxsGasValues.gasPrice.isZero()) {
        // Fetch current network gas price for replacement
        const currentGasPrice = await this.web3Provider.getGasPrice();
        oldTxsGasValues.gasPrice = currentGasPrice;
      }
    } else {
      // For EIP-1559 transactions
      if (
        !oldTxsGasValues.maxFeePerGas ||
        oldTxsGasValues.maxFeePerGas.isZero()
      ) {
        // Fetch current network fee data for replacement
        const feeData = await this.getFeeDataWithDynamicMaxPriorityFeePerGas();
        oldTxsGasValues.maxFeePerGas = BigNumber.from(
          feeData.maxFeePerGas || 0
        );
        oldTxsGasValues.maxPriorityFeePerGas = BigNumber.from(
          feeData.maxPriorityFeePerGas || 0
        );
      }
    }

    if (!isLegacy) {
      const newGasValues = this.calculateNewGasValues(
        oldTxsGasValues,
        false,
        false
      );

      let adjustedValue = txValue;

      // For likely max sends, check if we need to adjust value
      if (
        isLikelyMaxSend &&
        newGasValues.gasLimit &&
        newGasValues.maxFeePerGas
      ) {
        const newGasCost = newGasValues.gasLimit.mul(newGasValues.maxFeePerGas);
        const newTotalCost = txValue.add(newGasCost);

        if (newTotalCost.gt(currentBalance)) {
          // If this is a contract call, we cannot adjust the value
          if (isContractCall) {
            console.error(
              '[SpeedUp] Cannot adjust value for contract call - rejecting speedup'
            );
            return {
              isSpeedUp: false,
              error: true,
              code: 'CONTRACT_CALL_MAX_SEND',
              message:
                'Cannot speed up a likely max-send contract call; value cannot be adjusted to fit new gas',
            } as any;
          }

          // For non-contract calls, reduce value to fit within balance (clamp at zero)
          adjustedValue = currentBalance.gt(newGasCost)
            ? currentBalance.sub(newGasCost)
            : Zero;
        }
      }

      txWithEditedFee = {
        from: tx.from,
        to: tx.to,
        nonce: tx.nonce,
        value: adjustedValue,
        data: txData,
        maxFeePerGas: newGasValues.maxFeePerGas,
        maxPriorityFeePerGas: newGasValues.maxPriorityFeePerGas,
        gasLimit: newGasValues.gasLimit,
        // Don't set type - let ethers auto-detect for EIP-1559
      };
    } else {
      const newGasValues = this.calculateNewGasValues(
        oldTxsGasValues,
        false,
        true
      );

      let adjustedValue = txValue;

      // For likely max sends, check if we need to adjust value
      if (isLikelyMaxSend && newGasValues.gasLimit && newGasValues.gasPrice) {
        const newGasCost = newGasValues.gasLimit.mul(newGasValues.gasPrice);
        const newTotalCost = txValue.add(newGasCost);

        if (newTotalCost.gt(currentBalance)) {
          // If this is a contract call, we cannot adjust the value
          if (isContractCall) {
            console.error(
              '[SpeedUp] Cannot adjust value for contract call - rejecting speedup'
            );
            return {
              isSpeedUp: false,
              error: true,
              code: 'CONTRACT_CALL_MAX_SEND',
              message:
                'Cannot speed up a likely max-send contract call; value cannot be adjusted to fit new gas',
            } as any;
          }

          // For non-contract calls, reduce value to fit within balance (clamp at zero)
          adjustedValue = currentBalance.gt(newGasCost)
            ? currentBalance.sub(newGasCost)
            : Zero;
        }
      }

      txWithEditedFee = {
        from: tx.from,
        to: tx.to,
        nonce: tx.nonce,
        value: adjustedValue,
        data: txData,
        gasLimit: newGasValues.gasLimit,
        gasPrice: newGasValues.gasPrice,
        type: 0, // Force Type 0 for legacy speedup
      };
    }

    // Ledger speedup handler
    const speedUpWithLedger = async () => {
      try {
        const resolvedParams = await resolveProperties(
          omit(txWithEditedFee, 'from')
        );
        const formatParams = {
          ...resolvedParams,
          nonce: resolvedParams.nonce
            ? Number(resolvedParams.nonce.toString())
            : undefined,
        };
        const txFormattedForEthers = isLegacy
          ? {
              ...formatParams,
              chainId: activeNetwork.chainId,
              type: 0, // Need explicit type for hardware wallet serialization
            }
          : {
              ...formatParams,
              chainId: activeNetwork.chainId,
              type: 2, // Need explicit type for hardware wallet serialization
            };

        const rawTx = serializeTransaction(txFormattedForEthers);
        const signature = await this.ledgerSigner.evm.signEVMTransaction({
          rawTx: rawTx.replace('0x', ''),
          accountIndex: activeAccountId,
        });

        const formattedSignature = {
          r: `0x${signature.r}`,
          s: `0x${signature.s}`,
          v: parseInt(signature.v, 16),
        };

        if (signature) {
          const signedTx = serializeTransaction(
            txFormattedForEthers,
            formattedSignature
          );
          const transactionResponse = await this.web3Provider.sendTransaction(
            signedTx
          );

          return {
            isSpeedUp: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isSpeedUp: false,
            error: true,
          };
        }
      } catch (error) {
        console.error(
          '[SpeedUp] Failed to send replacement transaction with Ledger:',
          error
        );
        const message = (error as any)?.message || String(error);
        const lower = message.toLowerCase();
        const code = lower.includes('underpriced')
          ? 'REPLACEMENT_UNDERPRICED'
          : lower.includes('known transaction') ||
            lower.includes('already known')
          ? 'REPLACEMENT_ALREADY_KNOWN'
          : 'REPLACEMENT_SEND_FAILED';
        return {
          isSpeedUp: false,
          error: true,
          code,
          message,
        } as any;
      }
    };

    // Trezor speedup handler
    const speedUpWithTrezor = async () => {
      try {
        const trezorCoin =
          activeNetwork.slip44 === 60 ? 'eth' : activeNetwork.currency;
        const formattedTx = await resolveProperties(
          omit(txWithEditedFee, 'from')
        );

        const txFormattedForTrezor: any = {
          ...formattedTx,
          gasLimit:
            typeof formattedTx.gasLimit === 'string'
              ? formattedTx.gasLimit
              : this.toHex0x(formattedTx.gasLimit, 'gasLimit'),
          value:
            typeof formattedTx.value === 'string'
              ? formattedTx.value
              : this.toHex0x(formattedTx.value, 'value'),
          nonce: this.toHex0x(formattedTx.nonce, 'nonce'),
          chainId: activeNetwork.chainId,
          type: isLegacy ? 0 : 2, // Need explicit type for hardware wallet serialization
        };

        if (formattedTx.data && formattedTx.data !== '0x') {
          txFormattedForTrezor.data = formattedTx.data;
        }

        if (isLegacy) {
          txFormattedForTrezor.gasPrice =
            typeof formattedTx.gasPrice === 'string'
              ? formattedTx.gasPrice
              : this.toHex0x(formattedTx.gasPrice, 'gasPrice');
        } else {
          txFormattedForTrezor.maxFeePerGas =
            typeof (formattedTx as any).maxFeePerGas === 'string'
              ? (formattedTx as any).maxFeePerGas
              : this.toHex0x((formattedTx as any).maxFeePerGas, 'maxFeePerGas');
          txFormattedForTrezor.maxPriorityFeePerGas =
            typeof (formattedTx as any).maxPriorityFeePerGas === 'string'
              ? (formattedTx as any).maxPriorityFeePerGas
              : this.toHex0x(
                  (formattedTx as any).maxPriorityFeePerGas,
                  'maxPriorityFeePerGas'
                );
        }

        const signature = await this.trezorSigner.signEthTransaction({
          coin: trezorCoin,
          tx: txFormattedForTrezor,
          index: activeAccountId.toString(),
          slip44: activeNetwork.slip44,
        });

        if (signature.success) {
          const signedTx = serializeTransaction(
            txFormattedForTrezor,
            signature.payload
          );
          const transactionResponse = await this.web3Provider.sendTransaction(
            signedTx
          );

          return {
            isSpeedUp: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isSpeedUp: false,
            error: true,
          };
        }
      } catch (error) {
        console.error(
          '[SpeedUp] Failed to send replacement transaction with Trezor:',
          error
        );
        const message = (error as any)?.message || String(error);
        const lower = message.toLowerCase();
        const code = lower.includes('underpriced')
          ? 'REPLACEMENT_UNDERPRICED'
          : lower.includes('known transaction') ||
            lower.includes('already known')
          ? 'REPLACEMENT_ALREADY_KNOWN'
          : 'REPLACEMENT_SEND_FAILED';
        return {
          isSpeedUp: false,
          error: true,
          code,
          message,
        } as any;
      }
    };

    // Regular wallet speedup handler
    const speedUpWithPrivateKey = async () => {
      try {
        const { decryptedPrivateKey } = this.getDecryptedPrivateKey();
        const transactionResponse = await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          txWithEditedFee
        );

        if (transactionResponse) {
          return {
            isSpeedUp: true,
            transaction: transactionResponse,
          };
        } else {
          return {
            isSpeedUp: false,
          };
        }
      } catch (error) {
        console.error(
          '[SpeedUp] Failed to send replacement transaction:',
          error
        );
        const message = (error as any)?.message || String(error);
        const lower = message.toLowerCase();
        const code = lower.includes('underpriced')
          ? 'REPLACEMENT_UNDERPRICED'
          : lower.includes('known transaction') ||
            lower.includes('already known')
          ? 'REPLACEMENT_ALREADY_KNOWN'
          : lower.includes('insufficient funds')
          ? 'INSUFFICIENT_FUNDS_REPLACEMENT'
          : 'REPLACEMENT_SEND_FAILED';
        return {
          isSpeedUp: false,
          error: true,
          code,
          message,
        } as any;
      }
    };

    // Route based on account type
    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await speedUpWithTrezor();
      case KeyringAccountType.Ledger:
        return await speedUpWithLedger();
      default:
        return await speedUpWithPrivateKey();
    }
  };
  sendSignedErc20Transaction = async ({
    receiver,
    tokenAddress,
    tokenAmount,
    isLegacy = false,
    maxPriorityFeePerGas,
    maxFeePerGas,
    gasPrice,
    decimals,
    gasLimit,
    saveTrezorTx,
  }: ISendSignedErcTransactionProps): Promise<IResponseFromSendErcSignedTransaction> => {
    const { decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { accounts, activeAccountType, activeAccountId, activeNetwork } =
      this.getState();
    const { address: activeAccountAddress } =
      accounts[activeAccountType][activeAccountId];
    ({ gasPrice, isLegacy, maxFeePerGas, maxPriorityFeePerGas } =
      await this.resolveEvmFeeParams({
        gasPrice,
        isLegacy,
        maxFeePerGas,
        maxPriorityFeePerGas,
      }));

    const sendERC20Token = async () => {
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc20Abi(),
          this.web3Provider as any
        );
        // Preserve zero-decimal tokens: use provided decimals when defined (including 0).
        const resolvedDecimals =
          decimals === undefined || decimals === null ? 18 : Number(decimals);
        const calculatedTokenAmount = parseUnits(
          tokenAmount as string,
          resolvedDecimals
        ).toBigInt();
        let transferMethod;
        if (isLegacy) {
          const overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            gasPrice,
            ...(gasLimit && { gasLimit }),
            type: 0, // Explicitly set Type 0 for legacy token transfers
          };
          transferMethod = await _contract.transfer.populateTransaction(
            receiver,
            calculatedTokenAmount,
            normalizeEthersOverrides(overrides)
          );
        } else {
          const overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            maxPriorityFeePerGas,
            maxFeePerGas,
            ...(gasLimit && { gasLimit }),
          };

          transferMethod = await _contract.transfer.populateTransaction(
            receiver,
            calculatedTokenAmount,
            normalizeEthersOverrides(overrides)
          );
        }

        return await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          {
            ...transferMethod,
            chainId: activeNetwork.chainId,
            from: activeAccountAddress,
            value: '0x0',
          }
        );
      } catch (error) {
        throw error;
      }
    };

    const sendERC20TokenOnLedger = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc20Abi(),
          this.web3Provider as any
        );

        const resolvedDecimals =
          decimals === undefined || decimals === null ? 18 : Number(decimals);
        const calculatedTokenAmount = parseUnits(
          tokenAmount as string,
          resolvedDecimals
        ).toBigInt();

        const txData = _contract.interface.encodeFunctionData('transfer', [
          receiver,
          calculatedTokenAmount,
        ]);

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('100000'); // ERC20 fallback

        let txFormattedForEthers;
        if (isLegacy) {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            gasPrice,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 0,
          };
        } else {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            maxFeePerGas,
            maxPriorityFeePerGas,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 2, // Need explicit type for hardware wallet serialization
          };
        }

        const rawTx = serializeTransaction(txFormattedForEthers);

        const signature = await this.ledgerSigner.evm.signEVMTransaction({
          rawTx: rawTx.replace('0x', ''),
          accountIndex: activeAccountId,
        });

        const formattedSignature = {
          r: `0x${signature.r}`,
          s: `0x${signature.s}`,
          v: parseInt(signature.v, 16),
        };
        if (signature) {
          try {
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              formattedSignature
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            saveTrezorTx && saveTrezorTx(finalTx);

            return finalTx as any;
          } catch (error) {
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        throw error;
      }
    };

    const sendERC20TokenOnTrezor = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc20Abi(),
          this.web3Provider as any
        );

        const resolvedDecimals =
          decimals === undefined || decimals === null ? 18 : Number(decimals);
        const calculatedTokenAmount = parseUnits(
          tokenAmount as string,
          resolvedDecimals
        ).toBigInt();

        const txData = _contract.interface.encodeFunctionData('transfer', [
          receiver,
          calculatedTokenAmount,
        ]);

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('100000'); // ERC20 fallback

        let txToBeSignedByTrezor;
        if (isLegacy) {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            gasPrice: this.toHex0x(gasPrice, 'gasPrice'),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
        } else {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            maxFeePerGas: this.toHex0x(maxFeePerGas, 'maxFeePerGas'),
            maxPriorityFeePerGas: this.toHex0x(
              maxPriorityFeePerGas,
              'maxPriorityFeePerGas'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
        }

        const signature = await this.trezorSigner.signEthTransaction({
          index: `${activeAccountId}`,
          tx: txToBeSignedByTrezor,
          coin: activeNetwork.currency,
          slip44: activeNetwork.slip44,
        });

        if (signature.success) {
          try {
            let txFormattedForEthers;
            if (isLegacy) {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                gasPrice,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 0,
              };
            } else {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                maxFeePerGas,
                maxPriorityFeePerGas,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 2, // Need explicit type for hardware wallet serialization
              };
            }
            signature.payload.v = parseInt(signature.payload.v, 16); //v parameter must be a number by ethers standards
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              signature.payload
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            saveTrezorTx && saveTrezorTx(finalTx);

            return finalTx as any;
          } catch (error) {
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        throw error;
      }
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await sendERC20TokenOnTrezor();
      case KeyringAccountType.Ledger:
        return await sendERC20TokenOnLedger();
      default:
        return (await sendERC20Token()) as any;
    }
  };

  sendSignedErc721Transaction = async ({
    receiver,
    tokenAddress,
    tokenId,
    isLegacy,
    maxPriorityFeePerGas,
    maxFeePerGas,
    gasPrice,
    gasLimit,
  }: ISendSignedErcTransactionProps): Promise<IResponseFromSendErcSignedTransaction> => {
    const { decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { accounts, activeAccountType, activeAccountId, activeNetwork } =
      this.getState();
    const { address: activeAccountAddress } =
      accounts[activeAccountType][activeAccountId];
    ({ gasPrice, isLegacy, maxFeePerGas, maxPriorityFeePerGas } =
      await this.resolveEvmFeeParams({
        gasPrice,
        isLegacy,
        maxFeePerGas,
        maxPriorityFeePerGas,
      }));
    const normalizedTokenId = BigNumber.from(tokenId ?? 0).toBigInt();

    const sendERC721Token = async () => {
      let transferMethod;
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc21Abi(),
          this.web3Provider as any
        );

        if (isLegacy) {
          const overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            gasPrice,
            ...(gasLimit && { gasLimit }),
            type: 0, // Explicitly set Type 0 for legacy NFT transfers
          };
          transferMethod = await _contract.transferFrom.populateTransaction(
            activeAccountAddress,
            receiver,
            normalizedTokenId,
            normalizeEthersOverrides(overrides)
          );
        } else {
          const overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            maxPriorityFeePerGas,
            maxFeePerGas,
            ...(gasLimit && { gasLimit }),
          };
          transferMethod = await _contract.transferFrom.populateTransaction(
            activeAccountAddress,
            receiver,
            normalizedTokenId,
            normalizeEthersOverrides(overrides)
          );
        }

        return await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          {
            ...transferMethod,
            chainId: activeNetwork.chainId,
            from: activeAccountAddress,
            value: '0x0',
          }
        );
      } catch (error) {
        throw error;
      }
    };

    const sendERC721TokenOnLedger = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc21Abi(),
          this.web3Provider as any
        );
        const txData = _contract.interface.encodeFunctionData('transferFrom', [
          activeAccountAddress,
          receiver,
          normalizedTokenId,
        ]);

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('150000'); // ERC721 fallback

        let txFormattedForEthers;
        if (isLegacy) {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            gasPrice,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 0,
          };
        } else {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            maxFeePerGas,
            maxPriorityFeePerGas,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 2, // Need explicit type for hardware wallet serialization
          };
        }

        const rawTx = serializeTransaction(txFormattedForEthers);

        const signature = await this.ledgerSigner.evm.signEVMTransaction({
          rawTx: rawTx.replace('0x', ''),
          accountIndex: activeAccountId,
        });

        const formattedSignature = {
          r: `0x${signature.r}`,
          s: `0x${signature.s}`,
          v: parseInt(signature.v, 16),
        };

        if (signature) {
          try {
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              formattedSignature
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            return finalTx as any;
          } catch (error) {
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        throw error;
      }
    };

    const sendERC721TokenOnTrezor = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc21Abi(),
          this.web3Provider as any
        );
        const txData = _contract.interface.encodeFunctionData('transferFrom', [
          activeAccountAddress,
          receiver,
          normalizedTokenId,
        ]);

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('150000'); // ERC721 fallback

        let txToBeSignedByTrezor;
        if (isLegacy) {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            gasPrice: this.toHex0x(gasPrice, 'gasPrice'),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
          console.log({ txToBeSignedByTrezor });
        } else {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            maxFeePerGas: this.toHex0x(maxFeePerGas, 'maxFeePerGas'),
            maxPriorityFeePerGas: this.toHex0x(
              maxPriorityFeePerGas,
              'maxPriorityFeePerGas'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
        }

        // For EVM networks, Trezor expects 'eth' regardless of the network's currency
        const trezorCoin =
          activeNetwork.slip44 === 60 ? 'eth' : activeNetwork.currency;
        const signature = await this.trezorSigner.signEthTransaction({
          index: `${activeAccountId}`,
          tx: txToBeSignedByTrezor,
          coin: trezorCoin,
          slip44: activeNetwork.slip44,
        });

        if (signature.success) {
          try {
            let txFormattedForEthers;
            if (isLegacy) {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                gasPrice,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 0,
              };
            } else {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                maxFeePerGas,
                maxPriorityFeePerGas,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 2, // Need explicit type for hardware wallet serialization
              };
            }
            signature.payload.v = parseInt(signature.payload.v, 16); //v parameter must be a number by ethers standards
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              signature.payload
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            return finalTx as any;
          } catch (error) {
            console.log({ error });
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        console.log({ errorDois: error });
        throw error;
      }
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await sendERC721TokenOnTrezor();
      case KeyringAccountType.Ledger:
        return await sendERC721TokenOnLedger();
      default:
        return (await sendERC721Token()) as any;
    }
  };

  sendSignedErc1155Transaction = async ({
    receiver,
    tokenAddress,
    tokenId,
    tokenAmount,
    isLegacy,
    maxPriorityFeePerGas,
    maxFeePerGas,
    gasPrice,
    gasLimit,
  }: ISendSignedErcTransactionProps): Promise<IResponseFromSendErcSignedTransaction> => {
    const { decryptedPrivateKey } = this.getDecryptedPrivateKey();
    const { accounts, activeAccountType, activeAccountId, activeNetwork } =
      this.getState();
    const { address: activeAccountAddress } =
      accounts[activeAccountType][activeAccountId];
    ({ gasPrice, isLegacy, maxFeePerGas, maxPriorityFeePerGas } =
      await this.resolveEvmFeeParams({
        gasPrice,
        isLegacy,
        maxFeePerGas,
        maxPriorityFeePerGas,
      }));

    const sendERC1155Token = async () => {
      let transferMethod;
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc55Abi(),
          this.web3Provider as any
        );

        // Use BigNumber to avoid JS number overflow/precision loss
        const amount = BigNumber.from(tokenAmount ?? '1');

        let overrides;
        if (isLegacy) {
          overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            gasPrice,
            ...(gasLimit && { gasLimit }),
            type: 0, // Explicitly set Type 0 for legacy ERC1155 transfers
          };
        } else {
          overrides = {
            nonce: await this.web3Provider.getTransactionCount(
              activeAccountAddress,
              'pending'
            ),
            maxPriorityFeePerGas,
            maxFeePerGas,
            ...(gasLimit && { gasLimit }),
          };
        }

        transferMethod = await _contract.safeTransferFrom.populateTransaction(
          activeAccountAddress,
          receiver,
          tokenId as number,
          amount.toBigInt(),
          [],
          normalizeEthersOverrides(overrides)
        );
        return await sendLocalEvmTransaction(
          this.web3Provider,
          decryptedPrivateKey,
          {
            ...transferMethod,
            chainId: activeNetwork.chainId,
            from: activeAccountAddress,
            value: '0x0',
          }
        );
      } catch (error) {
        throw error;
      }
    };

    const sendERC1155TokenOnLedger = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc55Abi(),
          this.web3Provider as any
        );

        const amount = BigNumber.from(tokenAmount ?? '1');

        const txData = _contract.interface.encodeFunctionData(
          'safeTransferFrom',
          [activeAccountAddress, receiver, tokenId, amount.toBigInt(), []]
        );

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('200000'); // ERC1155 fallback

        let txFormattedForEthers;
        if (isLegacy) {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            gasPrice,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 0,
          };
        } else {
          txFormattedForEthers = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: effectiveGasLimit,
            maxFeePerGas,
            maxPriorityFeePerGas,
            data: txData,
            nonce: transactionNonce,
            chainId: activeNetwork.chainId,
            type: 2, // Need explicit type for hardware wallet serialization
          };
        }

        const rawTx = serializeTransaction(txFormattedForEthers);

        const signature = await this.ledgerSigner.evm.signEVMTransaction({
          rawTx: rawTx.replace('0x', ''),
          accountIndex: activeAccountId,
        });

        const formattedSignature = {
          r: `0x${signature.r}`,
          s: `0x${signature.s}`,
          v: parseInt(signature.v, 16),
        };

        if (signature) {
          try {
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              formattedSignature
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            return finalTx as any;
          } catch (error) {
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        throw error;
      }
    };

    const sendERC1155TokenOnTrezor = async () => {
      const transactionNonce = await this.getRecommendedNonce(
        activeAccountAddress
      );
      try {
        const _contract = new Contract(
          tokenAddress,
          getErc55Abi(),
          this.web3Provider as any
        );

        const amount = BigNumber.from(tokenAmount ?? '1');

        const txData = _contract.interface.encodeFunctionData(
          'safeTransferFrom',
          [activeAccountAddress, receiver, tokenId, amount.toBigInt(), []]
        );

        // Use fallback gas limit if not provided (for auto-estimation)
        const effectiveGasLimit = gasLimit || this.toBigNumber('200000'); // ERC1155 fallback

        let txToBeSignedByTrezor;
        if (isLegacy) {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            gasPrice: this.toHex0x(gasPrice, 'gasPrice'),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
        } else {
          txToBeSignedByTrezor = {
            to: tokenAddress,
            value: '0x0',
            gasLimit: this.toHex0x(effectiveGasLimit, 'gasLimit'),
            maxFeePerGas: this.toHex0x(maxFeePerGas, 'maxFeePerGas'),
            maxPriorityFeePerGas: this.toHex0x(
              maxPriorityFeePerGas,
              'maxPriorityFeePerGas'
            ),
            nonce: this.toBigNumber(transactionNonce)._hex,
            chainId: activeNetwork.chainId,
            data: txData,
          };
        }

        const signature = await this.trezorSigner.signEthTransaction({
          index: `${activeAccountId}`,
          tx: txToBeSignedByTrezor,
          coin: activeNetwork.currency,
          slip44: activeNetwork.slip44,
        });

        if (signature.success) {
          try {
            let txFormattedForEthers;
            if (isLegacy) {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                gasPrice,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 0,
              };
            } else {
              txFormattedForEthers = {
                to: tokenAddress,
                value: '0x0',
                gasLimit: effectiveGasLimit,
                maxFeePerGas,
                maxPriorityFeePerGas,
                data: txData,
                nonce: transactionNonce,
                chainId: activeNetwork.chainId,
                type: 2, // Need explicit type for hardware wallet serialization
              };
            }
            signature.payload.v = parseInt(signature.payload.v, 16); //v parameter must be a number by ethers standards
            const signedTx = serializeTransaction(
              txFormattedForEthers,
              signature.payload
            );
            const finalTx = await this.web3Provider.sendTransaction(signedTx);

            return finalTx as any;
          } catch (error) {
            console.log({ error });
            throw error;
          }
        } else {
          throw new Error(`Transaction Signature Failed. Error: ${signature}`);
        }
      } catch (error) {
        console.log({ error });
        throw error;
      }
    };

    switch (activeAccountType) {
      case KeyringAccountType.Trezor:
        return await sendERC1155TokenOnTrezor();
      case KeyringAccountType.Ledger:
        return await sendERC1155TokenOnLedger();
      default:
        return (await sendERC1155Token()) as any;
    }
  };

  getRecommendedNonce = async (address: string) => {
    try {
      return await this.web3Provider.getTransactionCount(address, 'pending');
    } catch (error) {
      throw error;
    }
  };

  getFeeByType = async (type: string) => {
    const gasPrice = (await this.getRecommendedGasPrice(false)) as string;

    const low = this.toBigNumber(gasPrice)
      .mul(BigNumber.from('8'))
      .div(BigNumber.from('10'))
      .toString();

    const high = this.toBigNumber(gasPrice)
      .mul(BigNumber.from('11'))
      .div(BigNumber.from('10'))
      .toString();

    if (type === 'low') return low;
    if (type === 'high') return high;

    return gasPrice;
  };

  getGasLimit = async (toAddress: string) => {
    try {
      const estimated = await this.web3Provider.estimateGas({
        to: toAddress,
      });

      return Number(BigNumber.from(estimated).toString());
    } catch (error) {
      throw error;
    }
  };

  getTxGasLimit = async (tx: SimpleTransactionRequest) => {
    const hasCalldata = Boolean(
      tx.data && tx.data !== '0x' && tx.data !== '0x0'
    );

    try {
      // First attempt: standard estimation
      const estimated = await this.web3Provider.estimateGas(tx);

      // Add 20% buffer to the estimated gas
      const withBuffer = estimated.mul(120).div(100);

      // Apply an explicit per-network floor only when configured.
      if (
        this.gasOverrides.minGasLimit &&
        withBuffer.lt(this.gasOverrides.minGasLimit)
      ) {
        return this.gasOverrides.minGasLimit;
      }

      return withBuffer;
    } catch (error) {
      console.warn('Gas estimation failed:', error);

      if (hasCalldata) {
        const calldataFallback = BigNumber.from('100000');
        if (
          this.gasOverrides.minGasLimit &&
          calldataFallback.lt(this.gasOverrides.minGasLimit)
        ) {
          return this.gasOverrides.minGasLimit;
        }

        return calldataFallback;
      }

      // Try a simpler estimation for basic transfers
      try {
        const simpleEstimate = await this.web3Provider.estimateGas({
          to: tx.to,
          from: tx.from,
          value: tx.value || '0x0',
        });

        const withBuffer = simpleEstimate.mul(150).div(100); // 50% buffer for failed estimations
        if (
          this.gasOverrides.minGasLimit &&
          withBuffer.lt(this.gasOverrides.minGasLimit)
        ) {
          return this.gasOverrides.minGasLimit;
        }

        return withBuffer;
      } catch (secondError) {
        // Ultimate fallback
        console.warn(
          'Simple estimation also failed, using default',
          secondError
        );
        return this.gasOverrides.minGasLimit || BigNumber.from('100000');
      }
    }
  };

  getRecommendedGasPrice = async (formatted?: boolean) => {
    try {
      const gasPriceBN = await this.web3Provider.getGasPrice();

      if (formatted) {
        return {
          gwei: Number(formatUnits(gasPriceBN, 'gwei')).toFixed(2),
          ethers: formatEther(gasPriceBN),
        };
      }

      return gasPriceBN.toString();
    } catch (error) {
      throw error;
    }
  };

  getBalance = async (address: string) => {
    try {
      const balance = await this.web3Provider.getBalance(address);
      const formattedBalance = formatEther(balance);

      return parseFloat(formattedBalance); // Return full precision
    } catch (error) {
      throw error;
    }
  };

  private getTransactionTimestamp = async (
    transaction: TransactionResponse
  ) => {
    const { timestamp } = await this.web3Provider.getBlock(
      Number(transaction.blockNumber)
    );

    return {
      ...transaction,
      timestamp,
    } as TransactionResponse;
  };

  public setWeb3Provider(network: INetwork) {
    this.abortController.abort();
    this.abortController = new AbortController();

    // Check if network is a UTXO network to avoid creating web3 providers for blockbook URLs
    const isUtxoNetwork = this.isUtxoNetwork(network);

    if (isUtxoNetwork) {
      // For UTXO networks, don't create web3 providers at all since they won't be used
      console.log(
        '[EthereumTransactions] setWeb3Provider: Skipping web3Provider creation for UTXO network:',
        network.url
      );
      // Clear any existing providers for UTXO networks
      this._web3Provider = undefined as any;
      this._web3ProviderKey = undefined;
    } else {
      this._web3Provider = new CustomJsonRpcProvider(
        this.abortController.signal,
        network.url,
        network.chainId
      );
      this._web3ProviderKey = `${network.chainId}|${network.url ?? ''}`;
    }
  }

  public importAccount = (mnemonicOrPrivKey: string) => {
    if (isHexString(mnemonicOrPrivKey)) {
      return privateKeyToAccount(mnemonicOrPrivKey);
    }

    return deriveEvmAccountFromMnemonic(
      mnemonicOrPrivKey,
      getAddressDerivationPath('eth', 60, 0, false, 0)
    );
  };

  // Method to configure gas overrides for networks with validation issues
  public setGasOverrides(overrides: {
    minGasLimit?: string | BigNumber;
    minPriorityFee?: string | BigNumber;
    feeMultiplier?: number;
  }) {
    this.gasOverrides = {
      minGasLimit: overrides.minGasLimit
        ? BigNumber.from(overrides.minGasLimit)
        : undefined,
      minPriorityFee: overrides.minPriorityFee
        ? BigNumber.from(overrides.minPriorityFee)
        : undefined,
      feeMultiplier: overrides.feeMultiplier,
    };
  }

  // Get the current gas overrides
  public getGasOverrides() {
    return this.gasOverrides;
  }

  // Method to get safe fee data that works around network-specific validation issues
  public getSafeFeeData = async (forceLegacy: boolean = false) => {
    if (forceLegacy) {
      // For legacy transactions, just return gas price
      const gasPrice = await this.web3Provider.getGasPrice();
      const bufferedGasPrice = gasPrice.mul(110).div(100); // 10% buffer
      return {
        gasPrice: bufferedGasPrice,
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
      };
    }

    try {
      // Try EIP-1559 fees first
      const feeData = await this.getFeeDataWithDynamicMaxPriorityFeePerGas();

      // If fees are zero or too low, fallback to legacy
      if (
        !feeData.maxFeePerGas ||
        feeData.maxFeePerGas.isZero() ||
        !feeData.maxPriorityFeePerGas ||
        feeData.maxPriorityFeePerGas.isZero()
      ) {
        console.log('EIP-1559 fees invalid, falling back to legacy gas price');
        const gasPrice = await this.web3Provider.getGasPrice();
        const bufferedGasPrice = gasPrice.mul(110).div(100);
        return {
          gasPrice: bufferedGasPrice,
          maxFeePerGas: undefined,
          maxPriorityFeePerGas: undefined,
        };
      }

      return {
        gasPrice: undefined,
        maxFeePerGas: feeData.maxFeePerGas,
        maxPriorityFeePerGas: feeData.maxPriorityFeePerGas,
      };
    } catch (error) {
      console.warn('Failed to get EIP-1559 fees, using legacy:', error);
      const gasPrice = await this.web3Provider.getGasPrice();
      const bufferedGasPrice = gasPrice.mul(110).div(100);
      return {
        gasPrice: bufferedGasPrice,
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
      };
    }
  };
}
