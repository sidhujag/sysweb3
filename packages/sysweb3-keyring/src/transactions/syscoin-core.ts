import { INetworkType } from '@sidhujag/sysweb3-network';
import { ITxid } from '@sidhujag/sysweb3-utils';
import { Psbt } from 'bitcoinjs-lib';
import * as syscoinjs from 'syscoinjs-lib';
// import { BIP_84, ONE_HUNDRED_MILLION, SYSCOIN_BASIC_FEE } from 'utils';

import { formatUnits } from '../ethers-v6';
import {
  ISyscoinTransactions,
  ISyscoinTransactionFeeQuote,
  KeyringAccountType,
  accountType,
  type SyscoinOwnedReadOptions,
  type SyscoinOwnedSubmissionOptions,
} from '../types';
import { fetchBackendAccountCached } from '../utils/blockbook-cache';
import {
  ExcludedOutpoint,
  excludedOutpointIds,
  filterExcludedUtxos,
  assertNoExcludedInputs,
} from '../utils/excluded-utxos';
import { PsbtUtils } from '../utils/psbt';
import {
  assertPsbtAccountScope,
  type PsbtAccountScope,
} from '../utils/psbt-account-scope';

import type { SyscoinHDSigner } from '../signers';
import type { INetwork } from '@sidhujag/sysweb3-network';

/** A hardware operation receives only its selected public account/context. */
export interface ISyscoinHardwareSigningRequest {
  readonly account: Readonly<{ id: number; xpub: string }>;
  assertCurrent: () => void;
  getRawTransaction?: (txid: string) => Promise<unknown>;
  readonly network: Readonly<INetwork>;
  psbt: Psbt;
  scope: PsbtAccountScope;
  signal: AbortSignal;
}

/**
 * Trusted wallet-authority adapter, not an untrusted plugin entry point.
 * Implementations must preserve the reviewed unsigned transaction and enforce
 * device signature/account-scope validation before returning the signed PSBT.
 */
export type ISyscoinHardwareSigner = (
  request: ISyscoinHardwareSigningRequest
) => Promise<Psbt>;

export interface ISyscoinHardwareSigners {
  ledger?: ISyscoinHardwareSigner;
  trezor?: ISyscoinHardwareSigner;
}

export const createHardwareSignerUnavailableError = (hardware: string) =>
  Object.assign(new Error(`${hardware} signer is unavailable in this host`), {
    code: 'HARDWARE_SIGNER_UNAVAILABLE',
  });

const sweepError = (code: string, message: string) => ({
  error: true,
  code,
  message,
});

const sweepAtomicValue = (value: any) => {
  const text =
    typeof value === 'number'
      ? Number.isSafeInteger(value)
        ? String(value)
        : ''
      : typeof value === 'string' ||
        typeof value === 'bigint' ||
        syscoinjs.utils.BN.isBN(value)
      ? value.toString()
      : '';
  if (!/^\d+$/.test(text))
    throw sweepError(
      'INVALID_NATIVE_SWEEP_UTXOS',
      'Invalid native sweep atomic value.'
    );
  return new syscoinjs.utils.BN(text);
};

type EstimateFeeParams = {
  changeAddress: string;
  feeRateBN: any;
  outputs: { address: string; value: any; subtractFeeFrom?: boolean }[];
  txOptions: any;
  xpub: string;
  fundingUtxos?: any;
};

type BlockbookRead = Pick<SyscoinOwnedReadOptions, 'fetch' | 'signal'>;

function captureBlockbookRead(
  options: SyscoinOwnedReadOptions,
  assertContext: () => void
) {
  if (!options) throw new Error('Missing owned UTXO read');
  const { fetch, signal, assertCurrent: assertHost } = options;
  if (
    typeof fetch !== 'function' ||
    typeof assertHost !== 'function' ||
    typeof signal?.aborted !== 'boolean'
  )
    throw new Error('Invalid owned UTXO read');
  const assertCurrent = () => {
    if (signal.aborted)
      throw new Error('Wallet UTXO preparation context changed');
    const result: unknown = assertHost();
    if (result !== undefined) {
      if (
        result &&
        (typeof result === 'object' || typeof result === 'function')
      )
        void Promise.resolve(result).catch(() => undefined);
      throw new Error('Owned UTXO read requires a synchronous guard');
    }
    assertContext();
    if (signal.aborted)
      throw new Error('Wallet UTXO preparation context changed');
  };
  assertCurrent();
  const transport: BlockbookRead = Object.freeze({
    signal,
    async fetch(input, init) {
      assertCurrent();
      const response = await fetch(input, init);
      assertCurrent();
      return response;
    },
  });
  return { assertCurrent, transport };
}

async function readOwnedFee(
  explorerUrl: string,
  { assertCurrent, transport }: ReturnType<typeof captureBlockbookRead>
): Promise<number> {
  assertCurrent();
  const fee = await syscoinjs.utils.fetchEstimateFee(
    explorerUrl,
    1,
    undefined,
    transport
  );
  assertCurrent();
  return fee / 1024;
}

/** Public network fee estimate. It has no wallet, account or signing access. */
export async function readPublicSyscoinFee(
  explorerUrl: string,
  owner: SyscoinOwnedReadOptions
): Promise<number> {
  return readOwnedFee(
    explorerUrl,
    captureBlockbookRead(owner, () => undefined)
  );
}

/** Internal captured context for the keyring's existing read-only builder and address lookup. */
export type SyscoinUtxoReadContext = Readonly<{
  assertCurrent: () => void;
  network: Readonly<INetwork>;
  transport: BlockbookRead;
}>;

type OwnedPreparation = Readonly<{
  account: Readonly<{ address: string; xpub: string }>;
  accountType: KeyringAccountType;
  read: SyscoinUtxoReadContext;
}>;
type GetUtxoAddress = (
  xpub: string,
  isChangeAddress: boolean
) => Promise<string>;
type ReadOnlySigner = { main: any; getOwnedAddress?: GetUtxoAddress };

export class SyscoinTransactionsCore implements ISyscoinTransactions {
  // New separated transaction flow for better UX:
  // 1. Call getEstimateSysTransactionFee() - creates UNSIGNED PSBT and calculates fee
  // 2. Call signPSBT() - signs the PSBT with appropriate wallet (HD/Trezor/Ledger)
  // 3. Call sendTransaction() - admits and broadcasts the reviewed signed bytes
  //
  // This separation allows:
  // - Independent error handling for each step
  // - Better UX feedback (fee estimation, signing, broadcasting)
  // - Hardware wallet compatibility with proper PSBT enhancement

  private getSigner: () => {
    hd: SyscoinHDSigner;
    main: any;
  };
  private getReadOnlySigner: (read?: SyscoinUtxoReadContext) => ReadOnlySigner;
  private hardwareSigners: ISyscoinHardwareSigners;
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
  private captureSigningContext: (bindSessionRevision: boolean) => () => void;

  constructor(
    getSyscoinSigner: () => {
      hd: SyscoinHDSigner;
      main: any;
    },
    getReadOnlySigner: (read?: SyscoinUtxoReadContext) => ReadOnlySigner,
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
    hardwareSigners: ISyscoinHardwareSigners,
    captureSigningContext: (bindSessionRevision: boolean) => () => void
  ) {
    if (typeof captureSigningContext !== 'function')
      throw new Error('Missing UTXO signing context');
    this.getSigner = getSyscoinSigner;
    this.getReadOnlySigner = getReadOnlySigner;
    this.getState = getState;
    this.hardwareSigners = hardwareSigners;
    this.captureSigningContext = captureSigningContext;
  }

  private getTransactionPSBT = async (
    {
      txOptions,
      outputs,
      changeAddress,
      feeRateBN,
      xpub,
      fundingUtxos,
    }: EstimateFeeParams,
    main: any
  ) => {
    try {
      // Use syscoinjs-lib directly for transaction creation
      const result = await main.createTransaction(
        txOptions,
        changeAddress,
        outputs,
        feeRateBN,
        xpub, // sysFromXpubOrAddress
        ...(fundingUtxos ? [fundingUtxos] : [])
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

  private captureOwnedRead(options: SyscoinOwnedReadOptions): OwnedPreparation {
    if (!options) throw new Error('Missing owned UTXO read');
    const assertSession = this.captureSigningContext(true);
    const { activeNetwork, activeAccountId, activeAccountType, accounts } =
      this.getState();
    if (activeNetwork.kind !== INetworkType.Syscoin)
      throw new Error('Switch to UTXO chain');
    const selected = accounts[activeAccountType]?.[activeAccountId];
    if (!selected) throw new Error('Active account not found');
    const account = Object.freeze({
      address: selected.address,
      xpub: selected.xpub,
    });
    const network = Object.freeze({ ...activeNetwork });
    const read = captureBlockbookRead(options, () => {
      assertSession();
      const current = this.getState();
      const selected =
        current.accounts[current.activeAccountType]?.[current.activeAccountId];
      if (
        current.activeAccountId !== activeAccountId ||
        current.activeAccountType !== activeAccountType ||
        selected?.address !== account.address ||
        selected?.xpub !== account.xpub ||
        current.activeNetwork.kind !== network.kind ||
        current.activeNetwork.chainId !== network.chainId ||
        current.activeNetwork.slip44 !== network.slip44 ||
        current.activeNetwork.currency !== network.currency ||
        current.activeNetwork.url !== network.url
      )
        throw new Error('Wallet UTXO preparation context changed');
    });
    return {
      account,
      accountType: activeAccountType,
      read: Object.freeze({ ...read, network }),
    };
  }

  public getRecommendedFee = async (
    explorerUrl: string,
    ownedRead: SyscoinOwnedReadOptions
  ): Promise<number> => {
    const { read } = this.captureOwnedRead(ownedRead);
    if (explorerUrl !== read.network.url)
      throw new Error('Owned UTXO read endpoint changed');
    return readOwnedFee(explorerUrl, read);
  };

  // Internal method for signing with the HD signer
  private signPSBTWithSigner = async ({
    psbt,
    signer,
  }: {
    psbt: Psbt;
    signer: any;
  }): Promise<Psbt> => await signer.sign(psbt);

  private createNativeSweepPSBT = async (
    {
      txOptions,
      changeAddress,
      receivingAddress,
      feeRateBN,
      source,
      excluded,
    }: {
      txOptions: any;
      changeAddress: string;
      receivingAddress: string;
      feeRateBN: any;
      source: string;
      excluded: ReadonlySet<string>;
    },
    main: any,
    read: SyscoinUtxoReadContext
  ): Promise<ISyscoinTransactionFeeQuote> => {
    const raw = await syscoinjs.utils.fetchBackendUTXOS(
      main.blockbookURL,
      source,
      undefined,
      read.transport
    );
    read.assertCurrent();
    const rows = excluded.size
      ? filterExcludedUtxos(raw, excluded).utxos
      : Array.isArray(raw)
      ? raw
      : raw?.utxos;
    if (!Array.isArray(rows))
      throw sweepError(
        'INVALID_NATIVE_SWEEP_UTXOS',
        'Invalid native sweep UTXO response.'
      );

    const seen = new Set<string>();
    const expected = new Set<string>();
    let gross = new syscoinjs.utils.BN(0);
    const utxos: any[] = [];
    for (const row of rows) {
      const txid = row?.txId ?? row?.txid;
      if (
        typeof txid !== 'string' ||
        !/^[0-9a-fA-F]{64}$/.test(txid) ||
        !Number.isSafeInteger(row.vout) ||
        row.vout < 0 ||
        row.vout > 0xffffffff ||
        (row.txId !== undefined &&
          row.txid !== undefined &&
          row.txId !== row.txid) ||
        (row.assetInfo != null &&
          (typeof row.assetInfo !== 'object' || Array.isArray(row.assetInfo)))
      )
        throw sweepError(
          'INVALID_NATIVE_SWEEP_UTXOS',
          'Invalid native sweep outpoint.'
        );
      const outpoint = `${txid.toLowerCase()}:${row.vout}`;
      if (seen.has(outpoint))
        throw sweepError(
          'INVALID_NATIVE_SWEEP_UTXOS',
          'Duplicate native sweep outpoint.'
        );
      seen.add(outpoint);
      const value = sweepAtomicValue(row.value);
      // Native MAX must leave asset carriers and their allocations untouched.
      if (row.assetInfo != null) continue;
      expected.add(outpoint);
      gross = gross.add(value);
      utxos.push({ ...row, value });
    }
    if (gross.isZero())
      throw sweepError(
        'INSUFFICIENT_FUNDS',
        'No native UTXOs are available to sweep.'
      );

    // The library sanitizes this snapshot once; its optional UTXO argument
    // prevents a second funding lookup between resolving MAX and building it.
    const result = await main.createTransaction(
      txOptions,
      changeAddress,
      [{ address: receivingAddress, value: gross, subtractFeeFrom: true }],
      feeRateBN,
      source,
      { utxos, assets: new Map() }
    );
    const inputs = result.psbt?.txInputs;
    const outputs = result.psbt?.txOutputs;
    const selected = Array.isArray(inputs)
      ? inputs.map(
          (input) =>
            `${Buffer.from(input.hash).reverse().toString('hex')}:${
              input.index
            }`
        )
      : [];
    if (
      selected.length !== expected.size ||
      new Set(selected).size !== expected.size ||
      selected.some((outpoint) => !expected.has(outpoint)) ||
      !Array.isArray(outputs) ||
      outputs.length !== 1
    )
      throw sweepError(
        'INCOMPLETE_NATIVE_SWEEP',
        'The builder did not preserve the complete native sweep.'
      );
    const script = syscoinjs.utils.bitcoinjs.address.toOutputScript(
      receivingAddress,
      main.network
    );
    const recipient = sweepAtomicValue(outputs[0].value);
    const fee = sweepAtomicValue(result.fee);
    if (
      !Buffer.from(outputs[0].script).equals(Buffer.from(script)) ||
      recipient.isZero() ||
      !recipient.add(fee).eq(gross)
    )
      throw sweepError(
        'INCOMPLETE_NATIVE_SWEEP',
        'The native sweep amounts do not match its PSBT.'
      );

    return {
      psbt: result.psbt,
      fee: result.fee,
      grossAmount: formatUnits(gross.toString(), 8).replace(/\.0$/, ''),
      recipientAmount: formatUnits(recipient.toString(), 8).replace(/\.0$/, ''),
    };
  };

  // Create unsigned PSBT for any transaction type
  private createUnsignedPSBT = async (
    {
      txOptions = {},
      isMax = false,
      nativeSweep = false,
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
      nativeSweep?: boolean;
    },
    owned: OwnedPreparation & {
      main: any;
      excluded: ReadonlySet<string>;
      getOwnedAddress: GetUtxoAddress;
    }
  ): Promise<ISyscoinTransactionFeeQuote> => {
    // Ensure RBF is enabled by default if not explicitly set
    const finalTxOptions = { rbf: true, ...txOptions };
    const {
      account,
      accountType: activeAccountType,
      excluded,
      main,
      read,
    } = owned;
    const xpub = account.xpub;
    const isSingleAddressImported =
      activeAccountType === KeyringAccountType.Imported &&
      xpub === account.address;

    // For imported extended-key accounts we store BIP84 xpubs (zpub/vpub).
    // Blockbook derives different address branches depending on version bytes, so preserve xpub as-is.
    const sourceForUtxoLookup = isSingleAddressImported
      ? account.address
      : xpub;
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
      : await owned.getOwnedAddress(xpub, true);
    read.assertCurrent();

    try {
      if (nativeSweep) {
        return await this.createNativeSweepPSBT(
          {
            txOptions: finalTxOptions,
            changeAddress,
            receivingAddress,
            feeRateBN,
            source: sourceForUtxoLookup,
            excluded,
          },
          main,
          read
        );
      }
      const fundingUtxos = excluded.size
        ? filterExcludedUtxos(
            await syscoinjs.utils.fetchBackendUTXOS(
              main.blockbookURL,
              sourceForUtxoLookup,
              undefined,
              read.transport
            ),
            excluded
          )
        : undefined;
      read.assertCurrent();
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
          sourceForUtxoLookup, // Pass source (address for WIF imports, zpub/vpub for HD)
          ...(fundingUtxos ? [fundingUtxos] : [])
        );

        if (excluded.size) assertNoExcludedInputs(result.psbt, excluded);

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
            xpub: sourceForUtxoLookup,
            fundingUtxos,
          },
          main
        );

        if (excluded.size) assertNoExcludedInputs(result.psbt, excluded);

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
    ownedRead: SyscoinUtxoReadContext
  ): Promise<Psbt> => {
    const { assertCurrent, network: activeNetwork, transport } = ownedRead;
    assertCurrent();
    const { activeAccountId, activeAccountType, accounts } = this.getState();
    const account = accounts[activeAccountType]?.[activeAccountId];
    if (!account) throw new Error('Active account not found');
    // Device choice belongs to the selected account, never to PSBT/caller flags.
    const isTrezor =
      activeAccountType === KeyringAccountType.Trezor ||
      account.isTrezorWallet === true;
    const isLedger =
      activeAccountType === KeyringAccountType.Ledger ||
      account.isLedgerWallet === true;
    const scope = Object.freeze({
      account: Object.freeze({ address: account.address, xpub: account.xpub }),
      accountId: activeAccountId,
      accountType: activeAccountType,
      network: activeNetwork,
    });
    const sign = isLedger
      ? this.hardwareSigners.ledger
      : isTrezor
      ? this.hardwareSigners.trezor
      : undefined;
    if ((isLedger || isTrezor) && typeof sign !== 'function')
      throw createHardwareSignerUnavailableError(
        isLedger ? 'Ledger' : 'Trezor'
      );
    if (isTrezor || isLedger) assertPsbtAccountScope(psbt, scope);

    if (isLedger || isTrezor) {
      const signed = await sign!({
        psbt,
        account: Object.freeze({ id: account.id, xpub: account.xpub }),
        network: scope.network,
        scope,
        assertCurrent,
        signal: transport.signal,
        ...(isLedger && {
          getRawTransaction: (txid: string) =>
            syscoinjs.utils.fetchBackendRawTx(
              activeNetwork.url,
              txid,
              transport
            ),
        }),
      });
      assertCurrent();
      return signed;
    } else {
      // HD signing (seed-based HDAccount or imported BIP84 zprv/vprv account).
      // Some Blockbook deployments return UTXOs without per-input derivation `path`,
      // which causes bitcoinjs-lib to throw "Need derivation path to sign with HD".
      //
      // We can recover by enriching PSBT inputs with a proprietary `path` field using
      // Blockbook's xpub token list (address -> path mapping), which reliably includes paths.
      const account = accounts[activeAccountType]?.[activeAccountId] as any;
      const accountXpub = account?.xpub as string | undefined;
      const accountAddress = account?.address as string | undefined;
      const isSingleAddressImported =
        activeAccountType === KeyringAccountType.Imported &&
        Boolean(accountXpub) &&
        Boolean(accountAddress) &&
        accountXpub === accountAddress;
      const isImportedExtended =
        activeAccountType === KeyringAccountType.Imported &&
        Boolean(accountXpub) &&
        !isSingleAddressImported;

      // IMPORTANT: Imported extended keys (zprv/vprv) are typically *account-level* keys.
      // syscoinjs-lib signs using the imported key as the BIP32 root, so PSBT `path` must be
      // relative (change/index), not the full `m/84'/.../change/index`. If we keep full paths,
      // bip32.derivePath can throw, leaving no derivations and causing "Need derivation path".
      if (isImportedExtended) {
        const inputs: any[] = (psbt as any)?.data?.inputs || [];
        for (const input of inputs) {
          const unknowns = input?.unknownKeyVals || [];
          const pathKv = unknowns.find(
            (kv) => kv?.key?.toString?.() === 'path'
          );
          if (!pathKv?.value) continue;
          const fullPath = String(Buffer.from(pathKv.value).toString());
          const parts = fullPath.split('/').filter(Boolean);
          // Expected: m/84'/slip44'/account'/change/index
          if (parts.length >= 2) {
            const change = parts[parts.length - 2];
            const index = parts[parts.length - 1];
            const rel = `${change}/${index}`;
            pathKv.value = Buffer.from(rel);
          }
        }
      }

      const needsAnyPath = (psbt as any)?.data?.inputs?.some((input) => {
        const unknowns = input?.unknownKeyVals || [];
        return (
          !input.bip32Derivation?.length &&
          !input.tapBip32Derivation?.length &&
          !unknowns.some((kv) => kv?.key?.toString?.() === 'path')
        );
      });

      if (
        needsAnyPath &&
        accountXpub &&
        !isSingleAddressImported &&
        typeof (psbt as any).addUnknownKeyValToInput === 'function'
      ) {
        // Fetch address->path mapping from Blockbook xpub endpoint
        // (in-flight deduplicated with the keyring's getAddress lookups)
        const blockbookUrl = activeNetwork.url;
        const res: any = await fetchBackendAccountCached(
          blockbookUrl,
          accountXpub,
          'tokens=used&details=tokens',
          transport
        );
        assertCurrent();
        const tokens: any[] = Array.isArray(res?.tokens) ? res.tokens : [];
        const addrToPath = new Map<string, string>();
        for (const t of tokens) {
          if (t?.name && t?.path) {
            addrToPath.set(String(t.name), String(t.path));
          }
        }

        const inputs: any[] = (psbt as any)?.data?.inputs || [];
        for (let i = 0; i < inputs.length; i++) {
          const input = inputs[i];
          const unknowns = input?.unknownKeyVals || [];
          const hasPath = unknowns.some(
            (kv) => kv?.key?.toString?.() === 'path'
          );
          if (hasPath) continue;

          const addrKv = unknowns.find(
            (kv) => kv?.key?.toString?.() === 'address'
          );
          const addr = addrKv?.value
            ? String(Buffer.from(addrKv.value).toString())
            : null;
          if (!addr) continue;

          const fullPath = addrToPath.get(addr);
          if (!fullPath) continue;

          // Imported extended keys are account-level (BIP84 account node), so we must provide a
          // path relative to that node (change/index), not the full m/84'/... path.
          const pathForSigner = isImportedExtended
            ? (() => {
                const parts = String(fullPath).split('/').filter(Boolean);
                // Expected: m/84'/slip44'/account'/change/index
                if (parts.length >= 2) {
                  const change = parts[parts.length - 2];
                  const index = parts[parts.length - 1];
                  return `${change}/${index}`;
                }
                return fullPath;
              })()
            : fullPath;

          (psbt as any).addUnknownKeyValToInput(i, {
            key: Buffer.from('path'),
            value: Buffer.from(pathForSigner),
          });
        }
      }

      assertCurrent();
      assertPsbtAccountScope(psbt, scope);
      const { hd } = this.getSigner();
      const signedPsbt = await this.signPSBTWithSigner({
        psbt,
        signer: hd,
      });
      assertCurrent();
      return signedPsbt;
    }
  };

  // Create unsigned PSBT and estimate fee - NO SIGNING
  public getEstimateSysTransactionFee = async (
    {
      txOptions = {},
      isMax = false,
      nativeSweep = false,
      amount,
      receivingAddress,
      feeRate,
      token = null,
      excludedOutpoints = [],
    }: {
      amount: number | string; // Accept both for safer precision handling
      feeRate?: number;
      receivingAddress: string;
      // Optional fee rate in SYS/byte
      token?: { guid: string; symbol?: string } | null;
      txOptions?: any;
      isMax?: boolean | false;
      nativeSweep?: boolean;
      excludedOutpoints?: readonly ExcludedOutpoint[];
    },
    ownedRead: SyscoinOwnedReadOptions
  ) => {
    try {
      if (
        nativeSweep !== false &&
        (nativeSweep !== true || isMax !== true || token !== null)
      )
        throw sweepError(
          'INVALID_NATIVE_SWEEP',
          'Native sweep requires explicit MAX and a native transaction.'
        );
      // Ensure RBF is enabled by default if not explicitly set
      const finalTxOptions = { rbf: true, ...txOptions };
      const preparation = this.captureOwnedRead(ownedRead);
      const { main, getOwnedAddress } = this.getReadOnlySigner(
        preparation.read
      );
      if (
        typeof getOwnedAddress !== 'function' ||
        main.blockbookURL !== preparation.read.network.url
      )
        throw new Error('Owned UTXO read adapter is unavailable');
      const owned = {
        ...preparation,
        main,
        getOwnedAddress,
        excluded: excludedOutpointIds(excludedOutpoints),
      };
      const selectedToken = token ? { ...token } : token;
      const { assetWhiteList } = finalTxOptions;
      if (assetWhiteList instanceof Map)
        finalTxOptions.assetWhiteList = new Map(assetWhiteList);
      else if (assetWhiteList instanceof Set)
        finalTxOptions.assetWhiteList = new Set(assetWhiteList);
      for (const key of ['memo', 'memoHeader', 'blobHash', 'blobData']) {
        const bytes = finalTxOptions[key];
        if (bytes instanceof Uint8Array)
          finalTxOptions[key] = Buffer.from(bytes);
      }
      const actualFeeRate =
        feeRate === undefined
          ? await readOwnedFee(main.blockbookURL, owned.read)
          : feeRate;
      owned.read.assertCurrent();

      // Convert fee rate to satoshis/byte and ensure minimum relay of 1 sat/vB
      // Blockbook returns coins per kB; after division by 1024, some testnets
      // can yield < 1 sat/vB (e.g., 0.9765625). Round up and clamp to 1 to
      // avoid zero-fee transactions due to truncation when converting to BN.
      const satPerByte = Math.max(1, Math.ceil(actualFeeRate * 1e8));
      const feeRateBN = new syscoinjs.utils.BN(satPerByte);

      // Step 2: Create unsigned PSBT
      const result = await this.createUnsignedPSBT(
        {
          txOptions: finalTxOptions,
          isMax,
          nativeSweep,
          amount,
          receivingAddress,
          feeRateBN,
          token: selectedToken,
        },
        owned
      );

      owned.read.assertCurrent();
      const quote = {
        fee: result.fee / 1e8,
        psbt: PsbtUtils.toPali(result.psbt), // Return UNSIGNED PSBT as JSON
        ...(nativeSweep
          ? {
              grossAmount: result.grossAmount,
              recipientAmount: result.recipientAmount,
            }
          : {}),
      };
      owned.read.assertCurrent();
      return quote;
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

  public signPSBT = async (
    { psbt }: { isLedger?: boolean; isTrezor?: boolean; psbt: any },
    ownedRead: SyscoinOwnedReadOptions
  ): Promise<any> => {
    const { read } = this.captureOwnedRead(ownedRead);
    const psbtObj = PsbtUtils.fromPali(psbt, read.network);
    const unsigned = Buffer.from(psbtObj.data.globalMap.unsignedTx.toBuffer());
    // Scope validation temporarily removes other signers' hints. Preserve the
    // public metadata for the next cosigner, without exposing it to our signer.
    const cosignerMetadata = psbtObj.data.inputs.map((input, index) => ({
      hash: Buffer.from(psbtObj.txInputs[index].hash),
      index: psbtObj.txInputs[index].index,
      bip32Derivation: input.bip32Derivation?.map((value) => ({ ...value })),
      tapBip32Derivation: input.tapBip32Derivation?.map((value) => ({
        ...value,
      })),
      path: input.unknownKeyVals
        ?.filter((value) => Buffer.from(value.key).toString() === 'path')
        .map((value) => ({
          key: Buffer.from(value.key),
          value: Buffer.from(value.value),
        }))[0],
    }));
    const signedPsbt = await this.signPSBTWithMethod(psbtObj, read);
    read.assertCurrent();
    if (!unsigned.equals(signedPsbt.data.globalMap.unsignedTx.toBuffer()))
      throw new Error('Signed PSBT differs from the prepared transaction');
    signedPsbt.data.inputs.forEach((input, index) => {
      if (input.finalScriptSig || input.finalScriptWitness) return;
      const metadata = cosignerMetadata[index];
      if (!metadata) return;
      const signed = signedPsbt.txInputs[index];
      if (
        !signed ||
        metadata.index !== signed.index ||
        !metadata.hash.equals(Buffer.from(signed.hash))
      )
        throw new Error('Wallet signing context changed');
      if (metadata.bip32Derivation)
        input.bip32Derivation = metadata.bip32Derivation;
      if (metadata.tapBip32Derivation)
        input.tapBip32Derivation = metadata.tapBip32Derivation;
      if (metadata.path) {
        input.unknownKeyVals = (input.unknownKeyVals || []).filter(
          (value) => Buffer.from(value.key).toString() !== 'path'
        );
        input.unknownKeyVals.push(metadata.path);
      }
    });
    const result = PsbtUtils.toPali(signedPsbt);
    read.assertCurrent();
    return result;
  };

  public sendTransaction = async (
    rawTransaction: string,
    authority: SyscoinOwnedSubmissionOptions
  ): Promise<ITxid> => {
    let read: SyscoinUtxoReadContext;
    let fetch: SyscoinOwnedSubmissionOptions['fetch'];
    let signal: AbortSignal;
    let prepare: SyscoinOwnedSubmissionOptions['prepare'];
    try {
      if (!authority) throw new Error('Missing owned UTXO submission context');
      const { assertCurrent } = authority;
      ({ fetch, signal, prepare } = authority);
      if (typeof prepare !== 'function')
        throw new Error('Missing UTXO submission admission');
      ({ read } = this.captureOwnedRead({ assertCurrent, fetch, signal }));
    } catch {
      throw Object.assign(new Error('UTXO submission was not dispatched'), {
        code: 'UTXO_SUBMISSION_NOT_DISPATCHED',
        transactionNotBroadcast: true,
      });
    }

    // SyscoinJS owns the admission, final synchronous guard and exact ACK.
    // The POST uses the captured transport directly so a matching ACK can
    // still be observed after a host context change without a signal abort.
    const { result: txid } = await syscoinjs.utils.sendRawTransaction(
      read.network.url,
      rawTransaction,
      undefined,
      { assertCurrent: read.assertCurrent, fetch, prepare, signal }
    );
    return { txid };
  };
}
