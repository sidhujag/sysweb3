export type SentryScheme = 'bls-basic' | 'slh-dsa-shake-128s';
export type SentryEra = 'legacy-v3' | 'pq-v4';

export interface SentryChain {
  genesisHash: string;
  era: SentryEra;
}

/** Exact independently fetched Core GlobalKeyRecord. Hashes use display order. */
export interface SentryPQRecord {
  version: number;
  profile: number;
  keyVersion: number;
  publicKey: string;
  childKeyCommitmentHex: string;
  activatedHeight: number;
}

export interface SentryNodeState {
  proTxHash: string;
  operatorPublicKey: string;
  service: string;
  operatorPayoutScript: string;
  nevmAddress: string;
  globalKeyVersion?: number;
  pqRecord?: SentryPQRecord;
  collateralOutpoint?: { txid: string; vout: number };
}

export interface SentryOperationRequest {
  version: 1;
  operation: 'updateService';
  chain: SentryChain;
  transactionHex: string;
}

/** This context belongs to the wallet. Do not accept it from a dapp. */
export interface SentryReviewContext {
  chain: SentryChain;
  node: SentryNodeState;
  previousTransactions: string[];
  maxFeeSatoshis: string;
}

export interface SentryOperationReview {
  operation: 'updateService';
  scheme: SentryScheme;
  chain: SentryChain;
  proTxHash: string;
  changes: {
    service: { previous: string; next: string };
    operatorPayoutScript: { previous: string; next: string };
    nevmAddress: { previous: string; next: string };
  };
  feeSatoshis: string;
  inputCount: number;
  outputs: { valueSatoshis: string; scriptHex: string; isPayload: boolean }[];
  /** Digest in byte order passed to the cryptographic signer, not uint256 display order. */
  authorizationHash: string;
}

/** Never serialize this type into a dapp response, log, telemetry or URL. */
export interface SentryImportedKey {
  scheme: SentryScheme;
  publicKey: string;
  secretKey: string;
}

export interface SentryOperationResponse {
  version: 1;
  operation: 'updateService';
  transactionHex: string;
  operatorPublicKey: string;
  authorizationHash: string;
}

export interface SentryTxInput {
  txid: string;
  vout: number;
  sequence?: number;
}

export interface SentryTxOutput {
  valueSatoshis: string;
  scriptHex: string;
}

export interface BuildSentryServiceUpdate {
  chain: SentryChain;
  node: SentryNodeState;
  service?: string;
  operatorPayoutScript?: string;
  /** Undefined preserves the registered address; '' explicitly removes it. */
  nevmAddress?: string;
  inputs: SentryTxInput[];
  outputs: SentryTxOutput[];
  lockTime?: number;
}

export interface DecodedSentryTransaction {
  version: number;
  inputs: {
    txid: string;
    vout: number;
    scriptHex: string;
    sequence: number;
    witness: string[];
  }[];
  outputs: SentryTxOutput[];
  lockTime: number;
  txid: string;
  weight: number;
  virtualSize: number;
}
