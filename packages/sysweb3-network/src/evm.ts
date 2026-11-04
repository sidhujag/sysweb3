/** Activated EVM protocol limits shared by wallet hosts. No RPC or UI imports. */
export type EvmProtocolLimits = Readonly<{
  /** Maximum raw transaction gas field, not any separate execution-gas dimension. */
  maxTransactionGas?: string;
}>;

const unknownLimits: EvmProtocolLimits = Object.freeze({});
const eip7825Limits: EvmProtocolLimits = Object.freeze({
  maxTransactionGas: '16777216',
});
const sepoliaGlamsterdamLimits: EvmProtocolLimits = Object.freeze({
  maxTransactionGas: '4294967295',
});

// Ethereum mainnet and Hoodi retain the activated Fusaka / EIP-7825 raw gas cap.
// https://eips.ethereum.org/EIPS/eip-7825
// https://blog.ethereum.org/2025/11/06/fusaka-mainnet-announcement
// Sepolia activated Glamsterdam at epoch 353024, 2026-10-06 13:53:36 UTC.
// EIP-8037 caps total tx.gas at 2^32-1; EIP-7825's 2^24 caps execution only.
// https://blog.ethereum.org/2026/09/17/glamsterdam-testnet-announcement
// https://eips.ethereum.org/EIPS/eip-8037#transaction-validation
// These are activated rules, not a future wall-clock schedule or an EVM/L2 default.
// The private map is read-only; callers only receive frozen metadata values.
const limitsByChainId: ReadonlyMap<bigint, EvmProtocolLimits> = new Map([
  [1n, eip7825Limits],
  [11155111n, sepoliaGlamsterdamLimits],
  [560048n, eip7825Limits],
]);

/** Lookup only: transaction admission separately validates the chain ID. */
export function getEvmProtocolLimits(chainId: bigint): EvmProtocolLimits {
  return limitsByChainId.get(chainId) ?? unknownLimits;
}
