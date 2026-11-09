import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';
import {
  computeAddress,
  getAddress,
  hashMessage,
  recoverAddress,
  Signature,
  Transaction,
} from 'ethers';

import { captureHardwareSigningData } from '../hardware-signing-data';
import {
  assertHardwareOperationCurrent,
  captureHardwareTransactionAuthority,
} from '../hardware-transaction-authority';
import { ConnectionStatus, HardwareWalletType } from '../hardware-wallet-types';
import { ledgerCancelledError, ledgerHostError } from './host-types';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';
import type { HardwareWalletManager } from '../hardware-wallet-manager';
import type {
  LedgerHost,
  LedgerOperationOptions,
  LedgerTypedData,
  LedgerUtxoHost,
} from './host-types';
import type { IEvmMethods, IUTXOMethods } from './types';

const invalidRequest = () =>
  ledgerHostError('LEDGER_INVALID_REQUEST', 'Invalid Ledger signing request');
const invalidSignature = () =>
  ledgerHostError(
    'LEDGER_INVALID_SIGNATURE',
    'Ledger returned an invalid signature for this request'
  );
const hostActivity = new WeakMap<LedgerHost, number>();

const accountIndex = (value: number) => {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0x7fffffff)
    throw invalidRequest();
  return value;
};
const hexBytes = (value: string): Uint8Array => {
  if (typeof value !== 'string' || !/^(?:0x)?(?:[0-9a-f]{2})*$/i.test(value))
    throw invalidRequest();
  return Uint8Array.from(Buffer.from(value.replace(/^0x/i, ''), 'hex'));
};
const approvedAddress = (value: string) => {
  try {
    return getAddress(value);
  } catch {
    throw invalidRequest();
  }
};
const checkedSignature = (
  value: string | { r: string; s: string; v: string },
  digest: string,
  expected: string
) => {
  try {
    let signature: Signature;
    if (typeof value === 'string') {
      if (!/^0x[0-9a-f]{130}$/i.test(value)) throw invalidSignature();
      signature = Signature.from(value);
    } else {
      if (
        !value ||
        !/^[0-9a-f]{64}$/i.test(value.r) ||
        !/^[0-9a-f]{64}$/i.test(value.s) ||
        !/^[0-9a-f]+$/i.test(value.v)
      )
        throw invalidSignature();
      const v = Number.parseInt(value.v, 16);
      if (!Number.isSafeInteger(v) || v < 0) throw invalidSignature();
      signature = Signature.from({ r: `0x${value.r}`, s: `0x${value.s}`, v });
    }
    if (recoverAddress(digest, signature) !== expected)
      throw invalidSignature();
    return signature;
  } catch {
    throw invalidSignature();
  }
};
/** Small authority-side facade. Device SDKs belong exclusively in ledger-host. */
export class LedgerKeyring {
  public readonly evm: IEvmMethods;
  public readonly utxo: IUTXOMethods;
  private generation = 0;

  // Retain the first constructor position for existing shared-manager callers.
  // A manager alone cannot grant a new device capability.
  constructor(
    private readonly sharedHardwareWalletManager?: HardwareWalletManager,
    private readonly host?: LedgerHost
  ) {
    this.evm = {
      getEvmAddressAndPubKey: async (request) => {
        const approved = { accountIndex: accountIndex(request.accountIndex) };
        return this.run(async (host, assertCurrent) => {
          const result = await host.evm.getAddress(approved);
          assertCurrent();
          try {
            const address = getAddress(result.address);
            const publicKey = result.publicKey.replace(/^0x/i, '');
            if (computeAddress(`0x${publicKey}`) !== address)
              throw invalidRequest();
            return { address, publicKey };
          } catch {
            throw ledgerHostError(
              'LEDGER_INVALID_RESPONSE',
              'Ledger returned an invalid address or public key'
            );
          }
        });
      },
      signEVMTransaction: async (request, authority) => {
        const owner = captureHardwareTransactionAuthority(authority);
        const index = accountIndex(request.accountIndex);
        const expected = approvedAddress(request.expectedAddress);
        let transaction: Transaction;
        try {
          transaction = Transaction.from(
            `0x${Buffer.from(hexBytes(request.rawTx)).toString('hex')}`
          );
          if (transaction.signature || transaction.chainId <= 0n)
            throw invalidRequest();
        } catch {
          throw invalidRequest();
        }
        const approved = {
          accountIndex: index,
          expectedAddress: expected,
          unsignedTxHex: transaction.unsignedSerialized.replace(/^0x/, ''),
        };
        const digest = transaction.unsignedHash;
        try {
          return await this.run(async (host, assertCurrent) => {
            owner.assertCurrent();
            const result = await host.evm.signTransaction(approved, owner);
            owner.assertCurrent();
            assertCurrent();
            const signature = checkedSignature(result, digest, expected);
            if (
              signature.legacyChainId !== null &&
              signature.legacyChainId !== transaction.chainId
            )
              throw invalidSignature();
            return {
              r: signature.r.slice(2),
              s: signature.s.slice(2),
              v: signature.v.toString(16),
            };
          }, owner);
        } catch (error) {
          owner.assertCurrent();
          throw error;
        }
      },
      signPersonalMessage: async (request, authority) => {
        const owner = captureHardwareTransactionAuthority(authority);
        const expected = approvedAddress(request.expectedAddress);
        const messageHex = Buffer.from(hexBytes(request.message)).toString(
          'hex'
        );
        const digest = hashMessage(hexBytes(messageHex));
        const approved = {
          accountIndex: accountIndex(request.accountIndex),
          expectedAddress: expected,
          messageHex,
        };
        return this.run(async (host, assertCurrent) => {
          const result = await host.evm.signPersonalMessage(approved, {
            ...owner,
            assertCurrent,
          });
          assertCurrent();
          return checkedSignature(result, digest, expected).serialized;
        }, owner);
      },
      signTypedData: async (request, authority) => {
        const owner = captureHardwareTransactionAuthority(authority);
        const { version } = request;
        if (
          version !== SignTypedDataVersion.V3 &&
          version !== SignTypedDataVersion.V4
        )
          throw invalidRequest();
        const expected = approvedAddress(request.expectedAddress);
        const index = accountIndex(request.accountIndex);
        let data: LedgerTypedData, digest: string;
        try {
          data = captureHardwareSigningData(request.data, invalidRequest);
          digest = `0x${TypedDataUtils.eip712Hash(
            data as any,
            version
          ).toString('hex')}`;
        } catch {
          throw invalidRequest();
        }
        const approved = {
          accountIndex: index,
          expectedAddress: expected,
          data,
          version,
        };
        return this.run(async (host, assertCurrent) => {
          const result = await host.evm.signTypedData(approved, {
            ...owner,
            assertCurrent,
          });
          assertCurrent();
          return checkedSignature(result, digest, expected).serialized;
        }, owner);
      },
    };
    this.utxo = {
      getUtxoAddress: ({ coin, index, slip44 }) =>
        this.run((host) =>
          host.utxo.getAddress({ currency: coin, accountIndex: index, slip44 })
        ),
      getXpub: ({ coin, index, slip44 }) =>
        this.run((host) =>
          host.utxo.getXpub({
            currency: coin,
            accountIndex: index,
            slip44,
            // Import must remain available for paths the device classifies as
            // unusual. Ask for its confirmation once, without retrying denial.
            checkOnDevice: true,
          })
        ),
      verifyUtxoAddress: this.verifyUtxoAddress,
    };
  }

  private requireHost(): LedgerHost {
    if (!this.host)
      throw ledgerHostError(
        'HARDWARE_SIGNER_UNAVAILABLE',
        'Ledger requires an authorized device host'
      );
    return this.host;
  }

  private async run<T>(
    operation: (host: LedgerHost, assertCurrent: () => void) => Promise<T>,
    options?: LedgerOperationOptions
  ): Promise<T> {
    const generation = this.generation;
    const host = this.requireHost();
    const assertCurrent = () => {
      if (generation !== this.generation || options?.signal?.aborted)
        throw ledgerCancelledError();
      if (options?.assertCurrent)
        assertHardwareOperationCurrent(options.assertCurrent);
      if (generation !== this.generation || options?.signal?.aborted)
        throw ledgerCancelledError();
    };
    assertCurrent();
    hostActivity.set(host, (hostActivity.get(host) ?? 0) + 1);
    try {
      // A visible platform host owns discovery, permission and device selection.
      if (!host.getStatus().connected) {
        assertCurrent();
        const request = { useGrantedDevices: true };
        await (options
          ? host.connect(request, { ...options, assertCurrent })
          : host.connect(request));
        assertCurrent();
      }
      assertCurrent();
      const result = await operation(host, assertCurrent);
      assertCurrent();
      return result;
    } catch (error) {
      assertCurrent();
      throw error;
    }
  }

  public ensureConnection = async (): Promise<void> =>
    this.run(async () => undefined);

  public verifyUtxoAddress = (
    accountIndex: number,
    currency: string,
    slip44: number
  ): Promise<string> =>
    this.run((host) =>
      host.utxo.getAddress({
        accountIndex,
        currency,
        slip44,
        checkOnDevice: true,
      })
    );

  public signUtxoMessage = (
    request: Parameters<LedgerUtxoHost['signMessage']>[0],
    authority: HardwareTransactionAuthority
  ): Promise<string> => {
    const owner = captureHardwareTransactionAuthority(authority);
    const approved = Object.freeze({
      currency: request.currency,
      slip44: request.slip44,
      accountIndex: request.accountIndex,
      message: request.message,
      addressIndex: request.addressIndex,
      change: request.change,
      accountXpub: request.accountXpub,
    });
    return this.run(
      (host, assertCurrent) =>
        host.utxo.signMessage(approved, { ...owner, assertCurrent }),
      owner
    );
  };

  public signPsbt = async (
    request: Parameters<LedgerUtxoHost['signPsbt']>[0],
    authority: Parameters<LedgerUtxoHost['signPsbt']>[1]
  ): ReturnType<LedgerUtxoHost['signPsbt']> => {
    const owner = captureHardwareTransactionAuthority(authority);
    const approved = Object.freeze({
      currency: request.currency,
      slip44: request.slip44,
      accountIndex: request.accountIndex,
      accountXpub: request.accountXpub,
      psbtBase64: request.psbtBase64,
    });
    try {
      return await this.run(async (host, assertCurrent) => {
        owner.assertCurrent();
        const result = await host.utxo.signPsbt(approved, owner);
        owner.assertCurrent();
        assertCurrent();
        return result;
      }, owner);
    } catch (error) {
      owner.assertCurrent();
      throw error;
    }
  };

  public getStatus() {
    const connected = this.host?.getStatus().connected === true;
    return {
      type: HardwareWalletType.LEDGER,
      connected,
      status: connected
        ? ConnectionStatus.CONNECTED
        : ConnectionStatus.DISCONNECTED,
    };
  }

  public async destroy(): Promise<void> {
    // Revoke pending responses synchronously, before platform teardown awaits.
    this.generation++;
    const cleanup = this.sharedHardwareWalletManager?.destroy();
    const disconnect = this.host?.disconnect();
    await Promise.all([cleanup, disconnect]);
  }

  /** Complete teardown and prove that no shared-host operation has reopened it. */
  public async retire(): Promise<() => void> {
    const host = this.host;
    const activity = host && hostActivity.get(host);
    const [, assertHostRetired] = await Promise.all([
      this.destroy(),
      Promise.resolve().then(() => host?.retire()),
    ]);
    const assertRetired = () => {
      if (host) {
        assertHardwareOperationCurrent(assertHostRetired!);
        if (hostActivity.get(host) !== activity) throw ledgerCancelledError();
      }
    };
    assertRetired();
    return assertRetired;
  }
}
