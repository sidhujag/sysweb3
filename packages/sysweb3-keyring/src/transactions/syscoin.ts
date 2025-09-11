import { INetwork, getNetworkConfig } from '@sidhujag/sysweb3-network';
import { ITxid, txUtils } from '@sidhujag/sysweb3-utils';
import { Psbt } from 'bitcoinjs-lib';
import * as syscoinjs from 'syscoinjs-lib';
// import { BIP_84, ONE_HUNDRED_MILLION, SYSCOIN_BASIC_FEE } from 'utils';

import { LedgerKeyring } from '../ledger';
import { DefaultWalletPolicy } from '../ledger/bitcoin_client';
import { PsbtV2 } from '../ledger/bitcoin_client/lib/psbtv2';
import { DESCRIPTOR } from '../ledger/consts';
import { SyscoinHDSigner } from '../signers';
import { TrezorKeyring } from '../trezor';
import {
  ISyscoinTransactions,
  KeyringAccountType,
  accountType,
} from '../types';
import {
  getAccountDerivationPath,
  convertExtendedKeyVersion,
} from '../utils/derivation-paths';
import { PsbtUtils } from '../utils/psbt';

type EstimateFeeParams = {
  changeAddress: string;
  feeRateBN: any;
  outputs: { address: string; value: any; subtractFeeFrom?: boolean }[];
  txOptions: any;
  xpub: string;
};

export class SyscoinTransactions implements ISyscoinTransactions {
  // New separated transaction flow for better UX:
  // 1. Call getEstimateSysTransactionFee() - creates UNSIGNED PSBT and calculates fee
  // 2. Call signPSBT() - signs the PSBT with appropriate wallet (HD/Trezor/Ledger)
  // 3. Call sendTransaction() - broadcasts the signed PSBT
  //
  // This separation allows:
  // - Independent error handling for each step
  // - Better UX feedback (fee estimation, signing, broadcasting)
  // - Hardware wallet compatibility with proper PSBT enhancement

  private getSigner: () => {
    hd: SyscoinHDSigner;
    main: any;
  };
  private getReadOnlySigner: () => {
    main: any;
  };
  private trezor: TrezorKeyring;
  private ledger: LedgerKeyring;
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
  private getAddress: (
    xpub: string,
    isChangeAddress: boolean
  ) => Promise<string>;

  constructor(
    getSyscoinSigner: () => {
      hd: SyscoinHDSigner;
      main: any;
    },
    getReadOnlySigner: () => {
      main: any;
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
    getAddress: (xpub: string, isChangeAddress: boolean) => Promise<string>,
    ledgerSigner: LedgerKeyring,
    trezorSigner: TrezorKeyring
  ) {
    this.getSigner = getSyscoinSigner;
    this.getReadOnlySigner = getReadOnlySigner;
    this.getState = getState;
    this.getAddress = getAddress;
    this.trezor = trezorSigner;
    this.ledger = ledgerSigner;
  }

  private getTransactionPSBT = async (
    { txOptions, outputs, changeAddress, feeRateBN, xpub }: EstimateFeeParams,
    main: any
  ) => {
    try {
      // Use syscoinjs-lib directly for transaction creation
      const result = await main.createTransaction(
        txOptions,
        changeAddress,
        outputs,
        feeRateBN,
        xpub // sysFromXpubOrAddress
      );

      if (result && result.psbt) {
        return { psbt: result.psbt, fee: result.fee };
      }
      throw new Error('psbt not found');
    } catch (error) {
      // Propagate structured error from syscoinjs-lib
      if (error.error && error.code) {
        throw error;
      }
      // Wrap non-structured errors
      throw {
        error: true,
        code: 'TRANSACTION_CREATION_FAILED',
        message: error.message || 'Failed to create transaction',
        details: error,
      };
    }
  };

  public decodeRawTransaction = (psbtOrHex: any, isRawHex = false) => {
    const { main } = this.getReadOnlySigner();

    if (isRawHex) {
      // Handle raw transaction hex
      const bitcoinTx =
        syscoinjs.utils.bitcoinjs.Transaction.fromHex(psbtOrHex);
      return main.decodeRawTransaction(bitcoinTx);
    } else {
      // Handle PSBT format (existing behavior)
      const psbtObj = PsbtUtils.fromPali(
        psbtOrHex,
        this.getState().activeNetwork
      );
      return main.decodeRawTransaction(psbtObj);
    }
  };

  public getRecommendedFee = async (explorerUrl: string): Promise<number> =>
    (await syscoinjs.utils.fetchEstimateFee(explorerUrl, 1)) / 1024;

  public txUtilsFunctions = () => {
    const { getRawTransaction } = txUtils();
    return {
      getRawTransaction,
    };
  };

  // Internal method for signing with the HD signer
  private signPSBTWithSigner = async ({
    psbt,
    signer,
  }: {
    psbt: Psbt;
    signer: any;
  }): Promise<Psbt> => await signer.sign(psbt);

  // Create unsigned PSBT for any transaction type
  private createUnsignedPSBT = async ({
    txOptions = {},
    isMax = false,
    amount,
    receivingAddress,
    feeRateBN,
    token = null,
  }: {
    amount: number | string; // Accept both for safer precision handling
    feeRateBN: any; // BigNumber in satoshis/byte
    receivingAddress: string;
    token?: { guid: string; symbol?: string } | null;
    txOptions?: any;
    isMax?: boolean | false;
  }): Promise<{ psbt: Psbt; fee: number }> => {
    // Ensure RBF is enabled by default if not explicitly set
    const finalTxOptions = { rbf: true, ...txOptions };
    const { activeAccountId, accounts, activeAccountType } = this.getState();
    // Use read-only signer since we're just creating an unsigned PSBT
    const { main } = this.getReadOnlySigner();
    const account = accounts[activeAccountType]?.[activeAccountId];
    if (!account) {
      throw new Error('Active account not found');
    }
    const xpub = account.xpub;
    const isSingleAddressImported =
      activeAccountType === KeyringAccountType.Imported &&
      xpub === account.address;
    // Convert amount to satoshis (1 SYS = 1e8 satoshis)
    // Using BigNumber to prevent precision loss
    const amountStr = amount.toString();

    // Safe conversion without parseFloat to avoid precision loss
    // Split the string to handle decimal values properly
    const parts = amountStr.split('.');
    const integerPart = parts[0] || '0';
    const decimalPart = parts[1] || '';

    // Pad or truncate decimal part to 8 places (satoshi precision)
    const paddedDecimal = decimalPart.padEnd(8, '0').substring(0, 8);

    // Combine to get satoshis (integer + decimal as one number)
    const satoshiStr = integerPart + paddedDecimal;

    // Remove leading zeros but keep at least one digit
    const trimmedSatoshis = satoshiStr.replace(/^0+/, '') || '0';

    const value = new syscoinjs.utils.BN(trimmedSatoshis);
    // If this is a single-address imported account (WIF import), use the account.address for both from and change
    const changeAddress = isSingleAddressImported
      ? account.address
      : await this.getAddress(xpub, true);

    try {
      if (token && token.guid) {
        // Token transaction: use assetAllocationSend
        // Create a Map for the asset allocation
        const assetMap = new Map();
        assetMap.set(token.guid, {
          changeAddress,
          outputs: [
            {
              value: value as any,
              address: receivingAddress,
            },
          ],
        });

        // Pass xpub to get back just the PSBT without signing and sending
        // syscoinjs-lib will validate asset existence and sufficient balance
        const result = await main.assetAllocationSend(
          finalTxOptions,
          assetMap,
          changeAddress,
          feeRateBN,
          isSingleAddressImported ? account.address : xpub // Pass source
        );

        // Return PSBT and fee
        return { psbt: result.psbt, fee: result.fee };
      } else {
        // Native transaction: use getTransactionPSBT to create unsigned PSBT
        const outputs = [
          {
            address: receivingAddress,
            value: value, // Pass BN object directly
            ...(isMax && { subtractFeeFrom: true }), // Only add subtractFeeFrom if isMax is true
          },
        ];

        const result = await this.getTransactionPSBT(
          {
            txOptions: finalTxOptions,
            outputs,
            changeAddress,
            feeRateBN,
            xpub: isSingleAddressImported ? account.address : xpub,
          },
          main
        );

        return result;
      }
    } catch (error) {
      // Re-throw structured errors from syscoinjs-lib
      if (error.error && error.code) {
        throw error;
      }
      // Wrap other errors in structured format
      throw {
        error: true,
        code: 'TRANSACTION_CREATION_FAILED',
        message: error.message || 'Failed to create unsigned PSBT',
        details: error,
      };
    }
  };

  // Sign PSBT with appropriate method - separated for better error handling
  private signPSBTWithMethod = async (
    psbt: Psbt,
    isTrezor: boolean,
    isLedger = false
  ): Promise<Psbt> => {
    const { activeNetwork, activeAccountId, activeAccountType, accounts } =
      this.getState();

    if (isLedger) {
      // CRITICAL: Enhance PSBT with required Ledger fields
      const account = accounts[activeAccountType]?.[activeAccountId];
      if (!account) {
        throw new Error('Active account not found');
      }
      const accountXpub = account.xpub;
      const accountId = account.id;
      const enhancedPsbt = await this.ledger.convertToLedgerFormat(
        psbt,
        accountXpub,
        accountId,
        activeNetwork.currency,
        activeNetwork.slip44
      );

      // Get wallet policy for Ledger
      const fingerprint =
        await this.ledger.ledgerUtxoClient.getMasterFingerprint();

      const hdPath = getAccountDerivationPath(
        activeNetwork.currency,
        activeNetwork.slip44,
        accountId
      );

      // Convert stored/display zpub/vpub to device-friendly xpub/tpub for policy descriptor using network macros
      const { types: deviceTypes } = getNetworkConfig(
        activeNetwork.slip44,
        activeNetwork.currency
      );
      const devicePubMagicDec =
        activeNetwork.slip44 === 1
          ? (deviceTypes.xPubType as any).testnet.vpub
          : deviceTypes.xPubType.mainnet.zpub;
      const devicePubMagicHex = Number(devicePubMagicDec)
        .toString(16)
        .padStart(8, '0');
      const deviceXpub = convertExtendedKeyVersion(
        accountXpub,
        devicePubMagicHex
      );
      const xpubWithDescriptor = `[${hdPath}]${deviceXpub}`.replace(
        'm',
        fingerprint
      );
      const walletPolicy = new DefaultWalletPolicy(
        DESCRIPTOR,
        xpubWithDescriptor
      );

      // Register lazily and retrieve HMAC for silent operations thereafter
      let hmac: Buffer | null = null;
      if (typeof (this.ledger as any).getOrRegisterHmac === 'function') {
        hmac = await (this.ledger as any).getOrRegisterHmac(
          walletPolicy,
          fingerprint
        );
      }

      // Convert to PsbtV2 for direct signing without intermediate base64 encode/decode
      const psbtV2 = new PsbtV2().fromBitcoinJS(enhancedPsbt);
      const signatureEntries = await this.ledger.ledgerUtxoClient.signPsbt(
        psbtV2,
        walletPolicy,
        hmac
      );

      signatureEntries.forEach(([inputIndex, partialSig]) => {
        enhancedPsbt.updateInput(inputIndex, {
          partialSig: [partialSig],
        });
      });

      // Finalize all inputs
      enhancedPsbt.finalizeAllInputs();

      return enhancedPsbt;
    } else if (isTrezor) {
      // Handle Trezor signing for UTXO
      // Get network configuration for Trezor
      const networkConfig = getNetworkConfig(
        activeNetwork.slip44,
        activeNetwork.currency
      );
      const isTestnet = activeNetwork.slip44 === 1;
      const bitcoinjsNetwork = isTestnet
        ? networkConfig?.networks?.testnet
        : networkConfig?.networks?.mainnet;

      const trezorTx = this.trezor.convertToTrezorFormat({
        psbt,
        coin: activeNetwork.currency.toLowerCase(),
        network: bitcoinjsNetwork || undefined, // Pass network config for isScriptHash check
      });
      const signedPsbt = await this.trezor.signUtxoTransaction(trezorTx, psbt);
      return signedPsbt;
    } else {
      const { hd } = this.getSigner();
      const signedPsbt = await this.signPSBTWithSigner({
        psbt,
        signer: hd,
      });
      return signedPsbt;
    }
  };

  // Create unsigned PSBT and estimate fee - NO SIGNING
  public getEstimateSysTransactionFee = async ({
    txOptions = {},
    isMax = false,
    amount,
    receivingAddress,
    feeRate,
    token = null,
  }: {
    amount: number | string; // Accept both for safer precision handling
    feeRate?: number;
    receivingAddress: string;
    // Optional fee rate in SYS/byte
    token?: { guid: string; symbol?: string } | null;
    txOptions?: any;
    isMax?: boolean | false;
  }) => {
    try {
      // Ensure RBF is enabled by default if not explicitly set
      const finalTxOptions = { rbf: true, ...txOptions };
      // Use read-only signer since we're just estimating fees and creating unsigned PSBT
      const { main } = this.getReadOnlySigner();
      // Step 1: Determine fee rate
      let actualFeeRate;
      if (feeRate !== undefined) {
        actualFeeRate = feeRate;
      } else {
        actualFeeRate = await this.getRecommendedFee(main.blockbookURL);
      }

      // Convert fee rate to satoshis/byte and ensure minimum relay of 1 sat/vB
      // Blockbook returns coins per kB; after division by 1024, some testnets
      // can yield < 1 sat/vB (e.g., 0.9765625). Round up and clamp to 1 to
      // avoid zero-fee transactions due to truncation when converting to BN.
      const satPerByte = Math.max(1, Math.ceil(actualFeeRate * 1e8));
      const feeRateBN = new syscoinjs.utils.BN(satPerByte);

      // Step 2: Create unsigned PSBT
      const result = await this.createUnsignedPSBT({
        txOptions: finalTxOptions,
        isMax,
        amount,
        receivingAddress,
        feeRateBN,
        token,
      });

      return {
        fee: result.fee / 1e8,
        psbt: PsbtUtils.toPali(result.psbt), // Return UNSIGNED PSBT as JSON
      };
    } catch (error) {
      // Pass through structured errors from syscoinjs-lib
      if (error.error && error.code) {
        // Convert fee from satoshis to SYS if available
        if (error.fee !== undefined) {
          // If fee is a BN object, convert to number first
          if (typeof error.fee === 'object' && error.fee.toNumber) {
            error.fee = error.fee.toNumber() / 1e8;
          } else {
            error.fee = error.fee / 1e8;
          }
        }
        if (error.remainingFee !== undefined) {
          // If remainingFee is a BN object, convert to number first
          if (
            typeof error.remainingFee === 'object' &&
            error.remainingFee.toNumber
          ) {
            error.remainingFee = error.remainingFee.toNumber() / 1e8;
          } else {
            error.remainingFee = error.remainingFee / 1e8;
          }
        }
        if (error.shortfall !== undefined) {
          // If shortfall is a BN object, convert to number first
          if (typeof error.shortfall === 'object' && error.shortfall.toNumber) {
            error.shortfall = error.shortfall.toNumber() / 1e8;
          } else {
            error.shortfall = error.shortfall / 1e8;
          }
        }
        throw error;
      }
      // Wrap other errors
      throw {
        error: true,
        code: 'TRANSACTION_CREATION_FAILED',
        message: error.message || 'Failed to estimate transaction fee',
        details: error,
      };
    }
  };

  // Removed createAndSignSysTransaction - functionality merged into getEstimateSysTransactionFee

  private sendSignedTransaction = async (psbt): Promise<ITxid> => {
    try {
      // Use read-only signer since we're just broadcasting an already-signed transaction
      const { main } = this.getReadOnlySigner();
      // Send the transaction
      const result = await main.send(psbt);

      // Extract the transaction ID
      const txid = result.extractTransaction().getId();
      return { txid };
    } catch (error) {
      // Pass through structured errors
      if (error.error && error.code) {
        throw error;
      }
      // Wrap other errors
      throw {
        error: true,
        code: 'TRANSACTION_SEND_FAILED',
        message: error.message || 'Failed to send transaction',
        details: error,
      };
    }
  };

  public signPSBT = async ({
    psbt,
    isTrezor = false,
    isLedger = false,
  }: {
    psbt: any;
    isTrezor?: boolean;
    isLedger?: boolean;
  }): Promise<any> => {
    const psbtObj = PsbtUtils.fromPali(psbt, this.getState().activeNetwork);
    const signedPsbt = await this.signPSBTWithMethod(
      psbtObj,
      isTrezor,
      isLedger
    );
    return PsbtUtils.toPali(signedPsbt);
  };

  public sendTransaction = async (psbt: any): Promise<ITxid> => {
    if (!psbt) {
      throw new Error('Signed PSBT is required for broadcasting.');
    }
    return await this.sendSignedTransaction(
      PsbtUtils.fromPali(psbt, this.getState().activeNetwork)
    );
  };
}
