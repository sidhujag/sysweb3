/* eslint-disable camelcase */
import { verify } from '@bitcoinerlab/secp256k1';
import { TypedDataUtils, SignTypedDataVersion } from '@metamask/eth-sig-util';
import bitcoinops from 'bitcoin-ops';
import { Psbt } from 'bitcoinjs-lib';
import bs58check from 'bs58check';
import { Buffer } from 'buffer';
import { recoverAddress } from 'ethers';
import * as syscoinjs from 'syscoinjs-lib';

import { trezorResponseError } from './connect';
import { captureHardwareSigningData } from '../hardware-signing-data';
import { serializeWitness } from './witness';
import {
  assertHardwareOperationCurrent,
  captureHardwareTransactionAuthority,
} from '../hardware-transaction-authority';
import { HardwareWalletManager } from '../hardware-wallet-manager';
import { HardwareWalletType } from '../hardware-wallet-types';
import {
  getAccountDerivationPath,
  getAddressDerivationPath,
  isEvmCoin,
} from '../utils/derivation-paths';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';
import type { TrezorConnection, TrezorSigningSession } from './connect';
import type { LedgerTypedData } from '../ledger/host-types';
import type {
  AccountInfo,
  CoinSymbol,
  EthereumTransaction,
  EthereumTransactionEIP1559,
} from '@trezor/connect-webextension';

const bitcoinjs: any = (syscoinjs.utils as any).bitcoinjs;
const { p2wsh } = bitcoinjs.payments;
const { decompile } = bitcoinjs.script;
const { fromBech32 } = bitcoinjs.address;
const fromBase58Check = (value: string) => {
  try {
    return bitcoinjs.address.fromBase58Check(value);
  } catch (error) {
    // The former decoder also accepted a two-byte network version. Preserve
    // exactly that checksum-verified format without loading the legacy fork.
    const payload = bs58check.decode(value);
    if (payload.length === 22) {
      return {
        version: (payload[0] << 8) | payload[1],
        hash: payload.subarray(2),
      };
    }
    throw error;
  }
};

const initialHDPath = `m/44'/60'/0'/0/0`;
const DELAY_BETWEEN_POPUPS = 2000; // Increased from 1000ms to 2000ms for more reliable operation
const stripHexPrefix = (value: string) => {
  return value.startsWith('0x') || value.startsWith('0X')
    ? value.slice(2)
    : value;
};
const finalizedFields = (input: any) => {
  if (!input.finalScriptSig && !input.finalScriptWitness) return null;
  return {
    scriptSig: Buffer.from(input.finalScriptSig || []).toString('hex'),
    witness: input.finalScriptWitness
      ? Buffer.from(input.finalScriptWitness).toString('hex')
      : '00',
  };
};

export interface TrezorControllerState {
  hdPath: string;
  paths: Record<string, number>;
}

export class TrezorKeyring {
  public hdPath: string = initialHDPath;
  public publicKey: Buffer;
  public chainCode: Buffer;
  public paths: Record<string, number> = {};
  public model?: string;
  private hardwareWalletManager: HardwareWalletManager;
  private initialized = false;
  private lifecycleGeneration = 0;
  private retirementEpoch = 0;
  private unsubscribeTrezor?: () => void;
  private readonly onTrezorConnected = ({
    type,
  }: {
    type: HardwareWalletType;
  }) => {
    if (type === HardwareWalletType.TREZOR) {
      console.log('Trezor connected');
      this.initialized = true;
    }
  };
  private readonly onTrezorDisconnected = ({
    type,
  }: {
    type: HardwareWalletType;
  }) => {
    if (type === HardwareWalletType.TREZOR) {
      console.log('Trezor disconnected');
      this.initialized = false;
    }
  };

  constructor(private readonly connection: TrezorConnection) {
    this.publicKey = Buffer.from('', 'hex');
    this.chainCode = Buffer.from('', 'hex');
    this.hdPath = '';
    this.paths = {};
    if (!connection)
      throw new TypeError('Trezor requires an explicit connection');
    this.hardwareWalletManager = new HardwareWalletManager(
      undefined,
      connection
    );

    this.observeTrezor();
  }

  private observeTrezor(): void {
    // Manager destruction removes its listeners. Reusing an unlocked keyring
    // must restore these same callbacks without multiplying them on each init.
    if (
      !this.hardwareWalletManager
        .listeners('connected')
        .includes(this.onTrezorConnected)
    )
      this.hardwareWalletManager.on('connected', this.onTrezorConnected);
    if (
      !this.hardwareWalletManager
        .listeners('disconnected')
        .includes(this.onTrezorDisconnected)
    )
      this.hardwareWalletManager.on('disconnected', this.onTrezorDisconnected);
    if (!this.unsubscribeTrezor)
      this.unsubscribeTrezor = this.connection.subscribe((event) => {
        if (event.type === 'model') this.model = event.model;
      });
  }

  /**
   * Initialize Trezor script.
   */
  public async init(assertCurrent?: () => void): Promise<boolean> {
    assertCurrent?.();
    this.retirementEpoch++;
    const generation = this.lifecycleGeneration;
    this.observeTrezor();
    if (this.initialized) {
      return true;
    }

    // Add a small delay to ensure Chrome extension context is ready
    // This helps prevent "waiting for handshake" errors
    await new Promise((resolve) => setTimeout(resolve, 100));
    assertCurrent?.();
    if (generation !== this.lifecycleGeneration) return false;

    const result = await this.hardwareWalletManager.initializeTrezor();
    assertCurrent?.();
    if (generation !== this.lifecycleGeneration) return false;
    if (result) {
      this.initialized = true;
    }
    return result;
  }

  private async initSigning(
    session: TrezorSigningSession,
    assertCurrent: () => void
  ): Promise<boolean> {
    assertHardwareOperationCurrent(assertCurrent);
    this.retirementEpoch++;
    const generation = this.lifecycleGeneration;
    this.observeTrezor();
    if (this.initialized) return true;
    await new Promise((resolve) => setTimeout(resolve, 100));
    assertHardwareOperationCurrent(assertCurrent);
    if (generation !== this.lifecycleGeneration) return false;
    const result = await this.hardwareWalletManager.initializeTrezorOwned(
      session,
      assertCurrent
    );
    assertHardwareOperationCurrent(assertCurrent);
    if (generation !== this.lifecycleGeneration) return false;
    if (result) this.initialized = true;
    return result;
  }

  /**
   * Execute operation with automatic retry
   */
  private async executeWithRetry<T>(
    operation: () => Promise<T>,
    operationName: string,
    assertCurrent?: () => void,
    owned?: TrezorSigningSession
  ): Promise<T> {
    assertCurrent?.();
    // Ensure initialization first
    if (!this.initialized) {
      const initResult = owned
        ? await this.initSigning(owned, assertCurrent!)
        : await this.init(assertCurrent);
      assertCurrent?.();
      if (!initResult) {
        throw new Error('Failed to initialize Trezor');
      }
    }

    // For Trezor operations, use reduced retry config to prevent popup spam
    const trezorRetryConfig = {
      maxRetries: 1, // Only retry once
      baseDelay: 1000,
      maxDelay: 5000,
      backoffMultiplier: 2,
    };

    // Use hardware wallet manager's retry mechanism with custom config
    return this.hardwareWalletManager
      .retryOperation(
        async () => {
          if (assertCurrent) assertHardwareOperationCurrent(assertCurrent);
          try {
            const result = await operation();
            if (assertCurrent) assertHardwareOperationCurrent(assertCurrent);
            return result;
          } catch (error) {
            if (assertCurrent) assertHardwareOperationCurrent(assertCurrent);
            throw error;
          }
        },
        operationName,
        trezorRetryConfig
      )
      .catch(async (error) => {
        if (assertCurrent) assertHardwareOperationCurrent(assertCurrent);
        // Clean up Trezor state on failure
        const message = String(error.message || '').toLowerCase();
        if (
          message.includes('popup closed') ||
          message.includes('cancelled') ||
          message.includes('canceled') ||
          message.includes('denied')
        ) {
          this.initialized = false;
          // Dispose Trezor connection to clean up
          try {
            await (owned ? owned.dispose() : this.connection.dispose());
            if (assertCurrent) assertHardwareOperationCurrent(assertCurrent);
          } catch (disposeError) {
            console.log('Failed to dispose Trezor on error:', disposeError);
          }
        }
        throw error;
      });
  }

  /**
   * This return account info based in params provided.
   *
   * @param coin - network symbol. Example: eth, sys, btc
   * @param slip44 - network slip44 number
   * @param hdPath - path derivation. Example: m/84'/57'/0'
   * @param index - index of account for path derivation
   * @returns derivated account info or error
   */

  public async getAccountInfo({
    coin,
    slip44,
    hdPath,
    index,
  }: {
    coin: string;
    hdPath?: string;
    index?: number;
    slip44: number;
  }): Promise<AccountInfo> {
    return this.executeWithRetry(async () => {
      // Use dynamic path generation instead of hardcoded switch
      this.setHdPath(coin, index || 0, slip44);

      if (hdPath) this.hdPath = hdPath;

      // For EVM networks, getAccountInfo is not supported
      // We need to use getAddress instead
      if (slip44 === 60) {
        const addressResponse = await this.connection.ethereumGetAddress({
          path: this.hdPath,
          showOnTrezor: false,
        });

        if (!addressResponse.success) {
          throw trezorResponseError(addressResponse);
        }

        // Return a compatible AccountInfo structure
        return {
          descriptor: addressResponse.payload.address,
          balance: '0', // Balance is fetched separately for EVM
          empty: true,
          history: {
            total: 0,
            unconfirmed: 0,
          },
        } as AccountInfo;
      }

      // For UTXO networks, use the standard getAccountInfo
      const response = await this.connection.getAccountInfo({
        coin: coin as CoinSymbol,
        path: this.hdPath,
      });

      if (response.success) {
        return response.payload;
      }
      throw trezorResponseError(response);
    }, 'getAccountInfo');
  }

  /**
   * Gets the model, if known.
   * This may be `undefined` if the model hasn't been loaded yet.
   *
   * @returns
   */
  public getModel(): string | undefined {
    return this.model;
  }

  /**
   * This disposes the active Trezor Suite connection
   *
   * @returns void
   */

  public dispose() {
    this.lifecycleGeneration++;
    try {
      void this.connection.dispose().catch((error) => {
        console.log('Error disposing Trezor:', error);
      });
      this.initialized = false;
      // Clear any cached data
      this.publicKey = Buffer.from('', 'hex');
      this.chainCode = Buffer.from('', 'hex');
      this.hdPath = '';
      this.paths = {};
    } catch (error) {
      console.log('Error disposing Trezor:', error);
    }
  }

  /**
   * This verify if message is valid or not.
   *
   * @param coin - network symbol. Example: eth, sys, btc
   * @param address - account address that signed message
   * @param message - message to be verified. Example: 'Test message'
   * @param signature - signature received in sign method. Example: I6BrpivjCwZmScZ6BMAHWGQPo+JjX2kzKXU5LcGVfEgvFb2VfJuKo3g6eSQcykQZiILoWNUDn5rDHkwJg3EcvuY=
   * @returns derivated account info or error
   */

  public async verifyMessage({
    coin,
    address,
    message,
    signature,
  }: {
    address: string;
    coin: string;
    message: string;
    signature: string;
  }) {
    return this.executeWithRetry(async () => {
      let method = '';
      switch (coin) {
        case 'eth':
          method = 'ethereumVerifyMessage';
          break;
        default:
          method = 'verifyMessage';
      }
      // @ts-ignore
      const { success, payload } = await this.connection[method]({
        coin,
        address,
        message,
        signature,
      });

      if (success) {
        return { success, payload };
      }
      throw trezorResponseError({ payload });
    }, 'verifyMessage');
  }

  /**
   * This return account public key.
   *
   * @param coin - network symbol. Example: eth, sys, btc
   * @param slip44 - network slip44 number
   * @param hdPath - path derivation. Example: m/44'/57'/0'/0/0
   * @returns publicKey and chainCode
   */

  public async getPublicKey({
    coin,
    slip44,
    hdPath,
    index,
  }: {
    coin: string;
    hdPath?: string;
    index?: number;
    slip44: number;
  }) {
    this.setHdPath(coin, index || 0, slip44);

    if (hdPath) this.hdPath = hdPath;

    await new Promise((resolve) => setTimeout(resolve, DELAY_BETWEEN_POPUPS));

    try {
      // For EVM networks, use ethereumGetPublicKey
      if (slip44 === 60) {
        const { success, payload } = await this.connection.ethereumGetPublicKey(
          {
            path: this.hdPath,
            showOnTrezor: false,
          }
        );

        if (success) {
          const { publicKey } = payload;
          // For Ethereum, we don't get chainCode from ethereumGetPublicKey
          this.publicKey = Buffer.from(publicKey, 'hex');

          return {
            publicKey: `0x${publicKey}`,
            chainCode: '', // Ethereum doesn't use chainCode in the same way
          };
        }

        return { success: false, payload };
      }

      // For UTXO networks, use standard getPublicKey
      const { success, payload } = await this.connection.getPublicKey({
        coin: coin as CoinSymbol,
        path: this.hdPath,
      });

      if (success) {
        const { publicKey, chainCode } = payload;

        this.publicKey = Buffer.from(publicKey, 'hex');
        this.chainCode = Buffer.from(chainCode, 'hex');

        return {
          publicKey: `0x${this.publicKey.toString('hex')}`,
          chainCode: `0x${this.chainCode.toString('hex')}`,
        };
      }

      return { success: false, payload };
    } catch (error) {
      return error;
    }
  }

  public range(n: number) {
    return [...Array(n).keys()];
  }

  /**
   * This sign UTXO tx.
   *
   * @param coin - network symbol. Example: eth, sys, btc
   * @param inputs - utxo transaction inputs
   * @param outputs - utxo transaction outputs
   * @returns signature object
   */

  public async signUtxoTransaction(
    utxoTransaction: any,
    psbt: Psbt,
    authority: HardwareTransactionAuthority
  ) {
    const owner = captureHardwareTransactionAuthority(authority);
    const { assertCurrent } = owner;
    // Capture approval before the device await. Witnesses and scriptSigs are
    // signatures, but every unsigned transaction field must remain identical.
    const unsignedSnapshot = (transaction: any): string =>
      JSON.stringify({
        version: transaction.version,
        locktime: transaction.locktime,
        inputs: (transaction.txInputs || transaction.ins).map((input: any) => ({
          hash: Buffer.from(input.hash).toString('hex'),
          index: input.index,
          sequence: input.sequence,
        })),
        outputs: (transaction.txOutputs || transaction.outs).map(
          (output: any) => ({
            script: Buffer.from(output.script).toString('hex'),
            value: output.value.toString(),
          })
        ),
      });
    const approvedTransaction = unsignedSnapshot(psbt);
    const approvedFinalInputs = psbt.data.inputs.map(finalizedFields);
    const approvedPsbt = psbt.toBase64();
    const candidate = psbt.clone();
    const approvedSighashTypes = candidate.data.inputs.map(
      (input) => input.sighashType ?? 0x01
    );
    const payload = await this.connection.withOwnedSigning(owner, (session) =>
      this.executeWithRetry(
        async () => {
          assertCurrent();
          const response = await session.signTransaction(utxoTransaction);
          assertCurrent();
          if (!response.success) {
            throw trezorResponseError(response, 'Trezor sign failed: ');
          }
          return response.payload;
        },
        'signUtxoTransaction',
        assertCurrent,
        session
      )
    );
    assertCurrent();

    const tx = bitcoinjs.Transaction.fromHex(payload.serializedTx);
    if (
      unsignedSnapshot(tx) !== approvedTransaction ||
      unsignedSnapshot(psbt) !== approvedTransaction
    ) {
      throw new Error('Trezor returned a different unsigned transaction');
    }
    // Finalized inputs belong to another signer. Neither the device response
    // nor concurrent code may replace their approved scripts or witnesses.
    if (
      approvedFinalInputs.some((approved, index) => {
        const current = finalizedFields(psbt.data.inputs[index]);
        if (!approved) return current !== null;
        return (
          !current ||
          current.scriptSig !== approved.scriptSig ||
          current.witness !== approved.witness ||
          Buffer.from(tx.ins[index].script).toString('hex') !==
            approved.scriptSig ||
          serializeWitness(tx.ins[index].witness || []).toString('hex') !==
            approved.witness
        );
      })
    ) {
      throw new Error('Trezor changed an already-finalized input');
    }
    if (psbt.toBase64() !== approvedPsbt)
      throw new Error('Trezor signing PSBT changed while awaiting approval');
    const signatures: Array<{
      index: number;
      partialSig: Array<{ pubkey: Buffer; signature: Buffer }>;
    }> = [];
    for (const i of this.range(psbt.data.inputs.length)) {
      if (approvedFinalInputs[i]) continue;
      if (tx.ins[i].witness == null || tx.ins[i].witness.length !== 2) {
        throw new Error(
          'Please move your funds to a Segwit address: https://wiki.trezor.io/Account'
        );
      }
      const partialSig = [
        {
          pubkey: Buffer.from(tx.ins[i].witness[1]),
          signature: Buffer.from(tx.ins[i].witness[0]),
        },
      ];
      const { pubkey, signature } = partialSig[0];
      const expectedSighash = approvedSighashTypes[i];
      if (signature[signature.length - 1] !== expectedSighash)
        throw new Error(
          'Trezor signature does not match the approved sighash type'
        );
      candidate.updateInput(i, { partialSig });
      let valid = false;
      try {
        valid = candidate.validateSignaturesOfInput(
          i,
          (key, hash, value) => verify(hash, key, value),
          pubkey
        );
      } catch {
        // Invalid keys or script membership must fail before finalization.
      }
      if (!valid)
        throw new Error('Invalid Trezor signature for approved transaction');
      signatures.push({ index: i, partialSig });
    }

    for (const { index, partialSig } of signatures)
      psbt.updateInput(index, { partialSig });

    try {
      syscoinjs.utils.finalizePSBT(psbt);
    } catch (err) {
      console.log(err);
    }
    return psbt;
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

  public convertToAddressNFormat(path: string) {
    const pathArray = path.replace(/'/g, '').split('/');

    pathArray.shift();

    const addressN: any[] = [];

    for (const index in pathArray) {
      if (Number(index) <= 2 && Number(index) >= 0) {
        addressN[Number(index)] = Number(pathArray[index]) | 0x80000000;
      } else {
        addressN[Number(index)] = Number(pathArray[index]);
      }
    }

    return addressN;
  }
  public isScriptHash(address: string, networkInfo: any) {
    if (!networkInfo) {
      // If network info is not available, make a best guess based on address format
      // This is a fallback for hardware wallet scenarios
      if (this.isBech32(address)) {
        const decoded = fromBech32(address);
        return decoded.data.length === 32; // 32 bytes = P2WSH
      }
      // For non-bech32, we can't reliably determine without network info
      // Default to false (P2PKH) as it's more common
      return false;
    }

    if (!this.isBech32(address)) {
      const decoded = fromBase58Check(address);
      if (decoded.version === networkInfo.pubKeyHash) {
        return false;
      }
      if (decoded.version === networkInfo.scriptHash) {
        return true;
      }
    } else {
      const decoded = fromBech32(address);
      if (decoded.data.length === 20) {
        return false;
      }
      if (decoded.data.length === 32) {
        return true;
      }
    }
    throw new Error('isScriptHash: Unknown address type');
  }

  public isPaymentFactory(payment: any) {
    return (script: any) => {
      try {
        payment({ output: script });
        return true;
      } catch (err) {
        return false;
      }
    };
  }
  public isBech32(address: string) {
    try {
      fromBech32(address);
      return true;
    } catch (e) {
      return false;
    }
  }
  public isP2WSHScript(script: any) {
    this.isPaymentFactory(p2wsh)(script);

    return false;
  }

  public convertToTrezorFormat({ psbt, coin, network }: any) {
    const trezortx: any = {};

    trezortx.coin = coin;
    trezortx.version = psbt.version;
    trezortx.locktime = psbt.locktime;
    trezortx.inputs = [];
    trezortx.outputs = [];

    for (let i = 0; i < psbt.txInputs.length; i++) {
      const input = psbt.txInputs[i];
      const inputItem: any = {};
      inputItem.prev_index = input.index;
      const hashBuf = Buffer.from(input.hash);
      const prevHashHex = hashBuf.reverse().toString('hex'); // 64-char hex
      inputItem.prev_hash = prevHashHex;
      if (input.sequence !== undefined) inputItem.sequence = input.sequence;

      const dataInput = psbt.data.inputs[i];

      if (dataInput.finalScriptSig || dataInput.finalScriptWitness) {
        // A finalized co-signer input is supplied as public transaction data,
        // never as a private derivation request to this device.
        let prevout = dataInput.witnessUtxo;
        if (dataInput.nonWitnessUtxo) {
          const previous = bitcoinjs.Transaction.fromBuffer(
            Buffer.from(dataInput.nonWitnessUtxo)
          );
          const output = previous.outs[input.index];
          if (
            !Buffer.from(previous.getHash()).equals(Buffer.from(input.hash)) ||
            !output ||
            (prevout &&
              (!Buffer.from(prevout.script).equals(
                Buffer.from(output.script)
              ) ||
                prevout.value.toString() !== output.value.toString()))
          ) {
            throw new Error('Trezor external input has an invalid prevout');
          }
          prevout = output;
        }
        if (!prevout || prevout.value === undefined || !prevout.script) {
          throw new Error('Trezor external input is missing its prevout');
        }
        inputItem.script_type = 'EXTERNAL';
        inputItem.amount = prevout.value.toString();
        inputItem.script_pubkey = Buffer.from(prevout.script).toString('hex');
        if (dataInput.finalScriptSig)
          inputItem.script_sig = Buffer.from(dataInput.finalScriptSig).toString(
            'hex'
          );
        if (dataInput.finalScriptWitness)
          inputItem.witness = Buffer.from(
            dataInput.finalScriptWitness
          ).toString('hex');
        trezortx.inputs.push(inputItem);
        continue;
      }

      // Resolve derivation path for this input
      let resolvedPath: string | null = null;
      const tapDer =
        dataInput.tapBip32Derivation && dataInput.tapBip32Derivation.length > 0
          ? dataInput.tapBip32Derivation[0]
          : null;
      const b32Der =
        dataInput.bip32Derivation && dataInput.bip32Derivation.length > 0
          ? dataInput.bip32Derivation[0]
          : null;

      if (tapDer && tapDer.path) {
        resolvedPath = tapDer.path;
      } else if (b32Der && b32Der.path) {
        resolvedPath = b32Der.path;
      } else if (dataInput.unknownKeyVals && dataInput.unknownKeyVals.length) {
        for (const kv of dataInput.unknownKeyVals) {
          if (Buffer.isBuffer(kv.key) && kv.key.toString() === 'path') {
            resolvedPath = kv.value.toString();
            break;
          }
        }
      }

      if (!resolvedPath) {
        throw new Error(
          'convertToTrezorFormat: Missing path (tapBip32Derivation/bip32Derivation/unknownKeyVals)'
        );
      }

      // Map path to Trezor address_n
      inputItem.address_n = this.convertToAddressNFormat(resolvedPath);

      // Coerce witnessUtxo.script to Buffer for downstream helpers
      const inScriptBuf =
        dataInput && dataInput.witnessUtxo && dataInput.witnessUtxo.script
          ? Buffer.isBuffer(dataInput.witnessUtxo.script)
            ? dataInput.witnessUtxo.script
            : Buffer.from(dataInput.witnessUtxo.script)
          : Buffer.alloc(0);

      // Select Trezor script_type (detect Taproot explicitly)
      const isTaproot =
        inScriptBuf &&
        inScriptBuf.length === 34 &&
        inScriptBuf[0] === bitcoinops.OP_1 &&
        inScriptBuf[1] === 0x20;

      if (isTaproot) {
        inputItem.script_type = 'SPENDTAPROOT';
      } else {
        const scriptTypes = psbt.getInputType(i);
        switch (scriptTypes) {
          case 'multisig':
            inputItem.script_type = 'SPENDMULTISIG';
            break;
          case 'witnesspubkeyhash':
            inputItem.script_type = 'SPENDWITNESS';
            break;
          default:
            inputItem.script_type = this.isP2WSHScript(inScriptBuf)
              ? 'SPENDP2SHWITNESS'
              : 'SPENDADDRESS';
            break;
        }
      }

      trezortx.inputs.push(inputItem);
    }

    for (let i = 0; i < psbt.txOutputs.length; i++) {
      const output = psbt.txOutputs[i];
      const outputItem: any = {};
      const scriptBuf = Buffer.isBuffer(output.script)
        ? output.script
        : Buffer.from(output.script || []);
      const chunks = decompile(scriptBuf);

      // Debug logging to understand the output structure
      console.log(`[Trezor] Processing output ${i}:`, {
        value: output.value,
        valueType: typeof output.value,
        hasAddress: !!output.address,
        address: output.address,
        scriptLength: output.script?.length,
      });

      // Ensure value exists and convert properly
      if (output.value === undefined || output.value === null) {
        throw new Error(`Output ${i} has no value`);
      }

      // Handle different value types
      let amountStr: string;
      if (typeof output.value === 'bigint') {
        amountStr = output.value.toString();
      } else if (typeof output.value === 'number') {
        amountStr = output.value.toString();
      } else if (typeof output.value === 'string') {
        amountStr = output.value;
      } else {
        throw new Error(
          `Output ${i} has unexpected value type: ${typeof output.value}`
        );
      }

      outputItem.amount = amountStr;
      if (chunks && chunks[0] === bitcoinops.OP_RETURN) {
        outputItem.script_type = 'PAYTOOPRETURN';
        // @ts-ignore
        outputItem.op_return_data = Buffer.from(chunks[1]).toString('hex');
      } else {
        if (output && this.isBech32(output.address)) {
          // Any bech32 witness program (P2WPKH or P2WSH) signs as PAYTOWITNESS
          outputItem.script_type = 'PAYTOWITNESS';
        } else {
          outputItem.script_type = this.isScriptHash(output.address, network)
            ? 'PAYTOSCRIPTHASH'
            : 'PAYTOADDRESS';
        }
        if (output.address) outputItem.address = output.address;
      }

      // Validate that the output has required fields for Trezor
      if (
        outputItem.script_type === 'PAYTOADDRESS' ||
        outputItem.script_type === 'PAYTOSCRIPTHASH' ||
        outputItem.script_type === 'PAYTOWITNESS'
      ) {
        if (!outputItem.address) {
          console.error(
            `[Trezor] Output ${i} missing address for script type ${outputItem.script_type}`
          );
          throw new Error(
            `Output ${i} requires an address for script type ${outputItem.script_type}`
          );
        }
      }

      trezortx.outputs.push(outputItem);
    }
    return trezortx;
  }

  /**
   * This sign EVM tx.
   *
   * @param index - index of account for path derivation
   * @param tx - ethereum tx object
   * @returns signature object
   */
  public async signEthTransaction(
    {
      tx,
      index,
      coin,
      slip44,
    }: {
      index: string;
      tx: EthereumTransaction | EthereumTransactionEIP1559;
      coin: string;
      slip44: number;
    },
    authority: HardwareTransactionAuthority
  ) {
    const owner = captureHardwareTransactionAuthority(authority);
    return this.connection.withOwnedSigning(owner, (session) =>
      this.executeWithRetry(
        async () => {
          owner.assertCurrent();
          // Wait between popups
          await new Promise((resolve) =>
            setTimeout(resolve, DELAY_BETWEEN_POPUPS)
          );
          owner.assertCurrent();

          // Use dynamic path generation based on actual network parameters
          this.setHdPath(coin, Number(index) || 0, slip44);
          const request = { path: this.hdPath, transaction: tx };

          try {
            const response = await session.ethereumSignTransaction(request);
            owner.assertCurrent();
            if (response.success) return response;
            throw trezorResponseError(response);
          } catch (error) {
            owner.assertCurrent();
            throw error;
          }
        },
        'signEthTransaction',
        owner.assertCurrent,
        session
      )
    );
  }

  /**
   * This sign message.
   *
   * @param coin - network symbol. Example: eth, sys, btc
   * @param slip44 - network slip44 number
   * @param message - message to be signed. Example: 'Test message'
   * @param index - index of account for path derivation
   * @returns signature object
   */

  public async signMessage(
    request: {
      address: string;
      coin: string;
      index: number;
      message: string;
      slip44: number;
    },
    authority: HardwareTransactionAuthority
  ) {
    const owner = captureHardwareTransactionAuthority(authority);
    const { address, coin, index, message, slip44 } = request;
    if (
      typeof address !== 'string' ||
      typeof coin !== 'string' ||
      typeof message !== 'string'
    )
      throw new Error('Invalid message signing request');
    const path = isEvmCoin(coin, slip44)
      ? getAddressDerivationPath(coin, slip44, 0, false, index)
      : getAccountDerivationPath(coin, slip44, index);
    return this.connection.withOwnedSigning(owner, (session) =>
      this.executeWithRetry(
        async () => {
          owner.assertCurrent();
          await new Promise((resolve) =>
            setTimeout(resolve, DELAY_BETWEEN_POPUPS)
          );
          owner.assertCurrent();
          if (isEvmCoin(coin, slip44)) {
            // Preserve the established spacing between initialization and personal approval.
            await new Promise((resolve) =>
              setTimeout(resolve, DELAY_BETWEEN_POPUPS)
            );
            owner.assertCurrent();
            const response = await session.ethereumSignMessage({
              path,
              message: stripHexPrefix(message),
              hex: true,
            });
            owner.assertCurrent();
            if (!response.success) throw trezorResponseError(response);
            if (
              response.payload.address.toLowerCase() !== address.toLowerCase()
            )
              throw new Error('signature doesnt match the right address');
            return {
              signature: `0x${response.payload.signature}`,
              success: true,
            };
          }
          const response = await session.signMessage({
            path,
            coin: coin as CoinSymbol,
            message,
          });
          owner.assertCurrent();
          return response;
        },
        'signMessage',
        owner.assertCurrent,
        session
      )
    );
  }
  private _transformTypedData = (
    data: LedgerTypedData,
    version: SignTypedDataVersion
  ) => {
    if (
      !data.types ||
      typeof data.types !== 'object' ||
      Array.isArray(data.types)
    )
      throw new Error('Invalid typed signing request');
    // Nested values already belong to the bounded, immutable capture. Only
    // these semantic fields may influence either device hashes or verification.
    const emptyDomainType: LedgerTypedData['types'][string] = [];
    Object.freeze(emptyDomainType);
    const canonical = Object.freeze({
      types: Object.freeze({
        ...data.types,
        EIP712Domain:
          data.types.EIP712Domain === undefined
            ? emptyDomainType
            : data.types.EIP712Domain,
      }),
      primaryType: data.primaryType,
      domain: data.domain === undefined ? Object.freeze({}) : data.domain,
      message: data.message === undefined ? Object.freeze({}) : data.message,
    });
    const domainSeparatorHash = TypedDataUtils.eip712DomainHash(
      canonical as any,
      version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
    ).toString('hex');

    let messageHash: string | null = null;

    if (canonical.primaryType !== 'EIP712Domain') {
      messageHash = TypedDataUtils.hashStruct(
        canonical.primaryType,
        canonical.message,
        canonical.types,
        version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
      ).toString('hex');
    }

    return {
      canonical,
      domain_separator_hash: domainSeparatorHash,
      message_hash: messageHash,
    };
  };

  /**
   * EIP-712 Sign Typed Data
   */
  public async signTypedData(
    request: {
      address: string;
      data: LedgerTypedData;
      index: number;
      version: SignTypedDataVersion;
    },
    authority: HardwareTransactionAuthority
  ) {
    const owner = captureHardwareTransactionAuthority(authority);
    const { version, address, index } = request;
    if (
      version !== SignTypedDataVersion.V3 &&
      version !== SignTypedDataVersion.V4
    )
      throw new Error(
        'Trezor: V1 typed data signing is not supported. Please use V3 or V4.'
      );
    if (typeof address !== 'string' || !/^0x[0-9a-f]{40}$/i.test(address))
      throw new Error('Invalid typed-data signer address');
    const path = getAddressDerivationPath('eth', 60, 0, false, index);
    const data = captureHardwareSigningData(
      request.data,
      () => new Error('Invalid typed signing request')
    );
    const { canonical, domain_separator_hash, message_hash } =
      this._transformTypedData(data, version);
    const digest = `0x${TypedDataUtils.eip712Hash(
      canonical as any,
      version
    ).toString('hex')}`;
    const approved = Object.freeze({
      path,
      data: canonical,
      metamask_v4_compat: version === SignTypedDataVersion.V4,
      domain_separator_hash,
      message_hash: message_hash ?? '',
    });
    owner.assertCurrent();
    return this.connection.withOwnedSigning(owner, async (session) => {
      const signature = await this.executeWithRetry(
        async () => {
          owner.assertCurrent();
          await new Promise((resolve) =>
            setTimeout(resolve, DELAY_BETWEEN_POPUPS)
          );
          owner.assertCurrent();
          const response = await session.ethereumSignTypedData(approved);
          owner.assertCurrent();
          if (!response.success) throw trezorResponseError(response);
          if (address.toLowerCase() !== response.payload.address.toLowerCase())
            throw new Error('signature doesnt match the right address');
          return response.payload.signature;
        },
        'signTypedData',
        owner.assertCurrent,
        session
      );
      owner.assertCurrent();
      // Verify after transport retry has completed: rejecting this proof must
      // not trigger another device approval.
      let valid = false;
      try {
        valid =
          typeof signature === 'string' &&
          /^0x[0-9a-f]{130}$/i.test(signature) &&
          recoverAddress(digest, signature).toLowerCase() ===
            address.toLowerCase();
      } catch {
        /* Refuse malformed or mismatched proofs before release. */
      }
      owner.assertCurrent();
      if (!valid)
        throw new Error('Trezor returned an invalid typed-data signature');
      return signature;
    });
  }

  /**
   * Verify UTXO address by displaying it on the Trezor device
   * @param accountIndex - The account index
   * @param currency - The currency (coin type)
   * @param slip44 - The slip44 value for the network
   * @returns The verified address
   */
  public async verifyUtxoAddress(
    accountIndex: number,
    currency: string,
    slip44: number
  ): Promise<string | undefined> {
    return this.executeWithRetry(async () => {
      const fullPath = getAddressDerivationPath(
        currency,
        slip44,
        accountIndex,
        false, // Not a change address
        0
      );

      try {
        const { payload, success } = await this.connection.getAddress({
          path: fullPath,
          coin: currency as CoinSymbol,
          showOnTrezor: true, // This displays the address on device for verification
        });
        if (success) {
          return payload.address;
        }
        throw new Error('Address verification cancelled by user');
      } catch (error) {
        throw error;
      }
    }, 'verifyUtxoAddress');
  }

  /**
   * Check Trezor status
   */
  public getStatus() {
    return this.hardwareWalletManager
      .getStatus()
      .find((s) => s.type === HardwareWalletType.TREZOR);
  }

  /**
   * Clean up resources
   */
  public async destroy() {
    this.unsubscribeTrezor?.();
    this.unsubscribeTrezor = undefined;
    try {
      // First dispose Trezor Connect
      this.dispose();
      // Then destroy hardware wallet manager
      await this.hardwareWalletManager.destroy();
      this.initialized = false;
    } catch (error) {
      console.error('Error destroying Trezor keyring:', error);
    }
  }

  /** Wait for the old device call and transport ownership to be fully retired. */
  public async retire(): Promise<() => void> {
    const epoch = this.retirementEpoch;
    this.dispose();
    this.unsubscribeTrezor?.();
    this.unsubscribeTrezor = undefined;
    const [retirement, managerRetirement] = await Promise.allSettled([
      this.connection.retire(),
      this.hardwareWalletManager.destroy(),
    ] as const);
    if (retirement.status === 'rejected') throw retirement.reason;
    if (managerRetirement.status === 'rejected') throw managerRetirement.reason;
    const assertRetired = () => {
      if (epoch !== this.retirementEpoch || this.initialized)
        throw new Error('Trezor reopened after retirement');
      assertHardwareOperationCurrent(retirement.value);
    };
    assertRetired();
    return assertRetired;
  }
}
