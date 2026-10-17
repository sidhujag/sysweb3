import type {
  SentryChain,
  SentryNodeState,
  SentryPQRecord,
  SentryScheme,
  SentryTxInput,
  SentryTxOutput,
} from './types.js';

export type SentryAuthorityRole =
  | 'collateral'
  | 'owner'
  | 'operator'
  | 'voting';
export type SentryAuthorityScheme = SentryScheme | 'secp256k1';
export interface SentryAuthorityKey {
  role: SentryAuthorityRole;
  scheme: SentryAuthorityScheme;
  publicKey: string;
  secretKey: string;
}
export interface SentryNetworkEncoding {
  bech32Hrp: string;
  pubKeyHash: number;
  scriptHash: number;
}
export interface SentryManagementNode extends SentryNodeState {
  ownerKeyId: string;
  votingKeyId: string;
  payoutScript: string;
  pqOwnerRecord?: {
    publicKey: string;
    keyVersion: number;
    activatedHeight: number;
  };
  pqVotingPublicKey?: string;
  operatorRevoked?: boolean;
}
export interface SentryManagementRequest {
  version: 1;
  operation:
    | 'register'
    | 'updateRegistrar'
    | 'revoke'
    | 'registerOperator'
    | 'rotateOperator';
  chain: SentryChain;
  transactionHex: string;
}
export interface SentryManagementContext {
  chain: SentryChain;
  network: SentryNetworkEncoding;
  node?: SentryManagementNode;
  previousTransactions: string[];
  maxFeeSatoshis: string;
  /** Independently resolved Core preparation-phase capability, never a dapp toggle. */
  allowOperatorPreparation?: boolean;
  allowOwnerPreparation?: boolean;
  registration?: {
    collateralTransactionHex: string;
    collateralVout: number;
    requiredCollateralSatoshis: string;
  };
}
export interface SentryRequiredAuthorization {
  id: 'collateral' | 'owner' | 'operator' | 'newOwner' | 'newOperator';
  role: SentryAuthorityRole;
  scheme: SentryAuthorityScheme;
  /** Hash160 for secp256k1, complete public key for BLS/SLH. */
  keyIdentity: string;
  digest: string;
  context?: string;
  signed: boolean;
}
export interface SentryManagementReview {
  operation: SentryManagementRequest['operation'];
  chain: SentryChain;
  proTxHash?: string;
  feeSatoshis: string;
  outputs: Array<SentryTxOutput & { isPayload: boolean }>;
  fields: Record<string, string>;
  authorizations: SentryRequiredAuthorization[];
}
export interface SentryManagementResponse {
  version: 1;
  operation: SentryManagementRequest['operation'];
  transactionHex: string;
  signedAuthorization: SentryRequiredAuthorization['id'];
  complete: boolean;
}
interface Funding {
  chain: SentryChain;
  inputs: SentryTxInput[];
  outputs: SentryTxOutput[];
  lockTime?: number;
}
export interface BuildSentryRegistration extends Funding {
  collateralOutpoint: { txid: string; vout: number };
  service: string;
  ownerKeyId: string;
  votingKeyId: string;
  operatorPublicKey?: string;
  pqOwnerPublicKey?: string;
  pqVotingPublicKey?: string;
  operatorRewardBasisPoints: number;
  payoutScript: string;
}
export interface BuildSentryRegistrarUpdate extends Funding {
  node: SentryManagementNode;
  operatorPublicKey?: string;
  votingKeyId?: string;
  payoutScript?: string;
  pqOwnerPublicKey?: string;
  pqVotingPublicKey?: string;
  ownerPreparation?: boolean;
}
export interface BuildSentryRevocation extends Funding {
  node: SentryManagementNode;
  reason: 0 | 1 | 2 | 3;
}
export interface BuildSentryOperatorUpdate extends Funding {
  node: SentryManagementNode;
  mode: 'initial' | 'rotate';
  candidate: SentryPQRecord;
}
