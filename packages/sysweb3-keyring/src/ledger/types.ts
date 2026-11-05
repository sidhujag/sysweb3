import { SignTypedDataVersion } from '@metamask/eth-sig-util';

import type { HardwareTransactionAuthority } from '../hardware-transaction-authority';

export interface IUTXOMethods {
  getUtxoAddress: ({
    coin,
    index,
    slip44,
  }: {
    coin: string;
    index: number;
    slip44: number;
  }) => Promise<string>;
  getXpub: ({
    index,
    coin,
    slip44,
  }: {
    coin: string;
    index: number;
    slip44: number;
  }) => Promise<string>;
  verifyUtxoAddress: (
    accountIndex: number,
    currency: string,
    slip44: number
  ) => Promise<string>;
}

interface MessageTypeProperty {
  name: string;
  type: string;
}
export interface MessageTypes {
  [additionalProperties: string]: MessageTypeProperty[];
  EIP712Domain: MessageTypeProperty[];
}

export interface IEvmMethods {
  getEvmAddressAndPubKey: ({
    accountIndex,
  }: {
    accountIndex: number;
  }) => Promise<{
    address: string;
    publicKey: string;
  }>;
  signEVMTransaction: (
    request: {
      accountIndex: number;
      rawTx: string;
      expectedAddress: string;
    },
    authority: HardwareTransactionAuthority
  ) => Promise<{
    r: string;
    s: string;
    v: string;
  }>;
  signPersonalMessage: ({
    message,
    accountIndex,
  }: {
    accountIndex: number;
    message: string;
    expectedAddress: string;
  }) => Promise<string>;
  signTypedData: ({
    version,
    data,
    accountIndex,
  }: {
    accountIndex: number;
    data: any;
    expectedAddress: string;
    version: SignTypedDataVersion;
  }) => Promise<string>;
}
