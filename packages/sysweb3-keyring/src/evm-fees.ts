/** Standard EVM fee discovery shared by extension and restricted native hosts. */
import { getEvmProtocolLimits } from '@sidhujag/sysweb3-network/cjs/evm.js';

export interface EvmFeeReader {
  getGasPrice(): Promise<unknown>;
  getBlock(tag: 'latest'): Promise<{ baseFeePerGas?: unknown } | null>;
  send(
    method: 'eth_maxPriorityFeePerGas' | 'eth_feeHistory',
    params: unknown[]
  ): Promise<unknown>;
  readonly signal?: AbortSignal;
}

export interface EvmFeeOptions {
  /** The host retains responsibility for chain, endpoint and account binding. */
  assertCurrent?: () => void;
  signal?: AbortSignal;
  minPriorityFee?: unknown;
  /** Positive, whole percentage; the existing recommendation uses 250. */
  feeMultiplier?: number;
}

export type EvmFeeData = Readonly<{
  gasPrice: bigint;
  /** Absent only when the observed header has no base-fee field. */
  baseFeePerGas?: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
}>;

const MAX_FEE = (1n << 256n) - 1n;

/** A validated limit failed its wire bounds or an activated protocol bound. */
export class EvmGasLimitError extends Error {
  constructor(
    public readonly code:
      | 'SYSWEB3_EVM_GAS_LIMIT_INVALID'
      | 'SYSWEB3_EVM_GAS_LIMIT_EXCEEDED'
  ) {
    super(
      code === 'SYSWEB3_EVM_GAS_LIMIT_INVALID'
        ? 'Invalid EVM gas limit'
        : 'EVM gas limit exceeds the network limit'
    );
    this.name = 'EvmGasLimitError';
  }
}

/** The host supplies a verified chain and, if sampled, its block gas limit. */
export function assertEvmGasLimit(
  gasLimit: bigint,
  chainId: bigint,
  sampledBlockGasLimit?: bigint
): bigint {
  if (
    typeof gasLimit !== 'bigint' ||
    gasLimit <= 0n ||
    gasLimit > MAX_FEE ||
    typeof chainId !== 'bigint' ||
    chainId < 0n ||
    chainId > MAX_FEE ||
    (sampledBlockGasLimit !== undefined &&
      (typeof sampledBlockGasLimit !== 'bigint' ||
        sampledBlockGasLimit <= 0n ||
        sampledBlockGasLimit > MAX_FEE))
  )
    throw new EvmGasLimitError('SYSWEB3_EVM_GAS_LIMIT_INVALID');
  const { maxTransactionGas } = getEvmProtocolLimits(chainId);
  if (
    (maxTransactionGas !== undefined && gasLimit > BigInt(maxTransactionGas)) ||
    (sampledBlockGasLimit !== undefined && gasLimit > sampledBlockGasLimit)
  )
    throw new EvmGasLimitError('SYSWEB3_EVM_GAS_LIMIT_EXCEEDED');
  return gasLimit;
}

/** Accept the SDK's existing BigNumberish forms without permissive zero coercion. */
export function parseEvmFeeQuantity(
  value: unknown,
  label = 'fee quantity'
): bigint {
  if (value !== null && typeof value === 'object') {
    const object = value as {
      _hex?: unknown;
      hex?: unknown;
      toString?: () => unknown;
    };
    value =
      object._hex ??
      object.hex ??
      (typeof object.toString === 'function' ? object.toString() : undefined);
    if (typeof value !== 'string') throw new Error(`Invalid ${label}`);
  }
  if (
    !(
      (typeof value === 'string' &&
        value.length <= 80 &&
        /^(?:0x[\da-f]+|\d+)$/i.test(value)) ||
      (typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0) ||
      (typeof value === 'bigint' && value >= 0n)
    )
  )
    throw new Error(`Invalid ${label}`);
  const quantity = BigInt(value as string | number | bigint);
  if (quantity > MAX_FEE) throw new Error(`Invalid ${label}`);
  return quantity;
}

/**
 * The existing successful-estimate policy: floor(estimate * 120 / 100), then
 * the configured minimum if larger. Callers retain chain/resource bounds.
 */
export function bufferedEvmGasLimit(
  estimate: bigint,
  minimum?: bigint
): bigint {
  if (
    typeof estimate !== 'bigint' ||
    estimate < 0n ||
    (minimum !== undefined && typeof minimum !== 'bigint')
  )
    throw new Error('Invalid gas estimate');
  const buffered = (estimate * 120n) / 100n;
  return minimum !== undefined && minimum > buffered ? minimum : buffered;
}

export type EvmCancellationFeeInput = Readonly<
  | { type: 0; currentGasPrice: bigint; originalGasPrice?: bigint }
  | {
      type: 2;
      currentMaxFeePerGas: bigint;
      currentMaxPriorityFeePerGas: bigint;
      originalMaxFeePerGas?: bigint;
      originalMaxPriorityFeePerGas?: bigint;
    }
>;

/** Plan only the cancellation fees. The host validates the rates and envelope. */
export function planEvmCancellationFees(input: EvmCancellationFeeInput) {
  const gasLimit = 42000n;
  const higher = (left: bigint, right: bigint) => (left > right ? left : right);
  // The replacement must also bump zero and small rates by at least one wei.
  const bump = (fee: bigint) => higher((fee * 120n) / 100n, fee + 1n);
  if (input.type === 0) {
    const gasPrice = bump(
      higher(input.currentGasPrice, input.originalGasPrice ?? 0n)
    );
    return Object.freeze({
      type: 0 as const,
      gasLimit,
      gasPrice,
      maximumFee: gasLimit * gasPrice,
    });
  }
  const priority = higher(
    input.currentMaxPriorityFeePerGas,
    input.originalMaxPriorityFeePerGas ?? 0n
  );
  const cap = higher(
    input.currentMaxFeePerGas,
    input.originalMaxFeePerGas ?? 0n
  );
  const maxFeePerGas = bump(higher(cap, priority));
  return Object.freeze({
    type: 2 as const,
    gasLimit,
    maxFeePerGas,
    maxPriorityFeePerGas: bump(priority),
    maximumFee: gasLimit * maxFeePerGas,
  });
}

function unsupportedPriorityMethod(error: any): boolean {
  const unsupportedCode = (code: unknown) => code === -32601 || code === 4200;
  if (unsupportedCode(error?.code)) return true;
  if (!['UNKNOWN_ERROR', 'UNSUPPORTED_OPERATION'].includes(error?.code))
    return false;
  if (
    error?.operation != null &&
    error.operation !== 'eth_maxPriorityFeePerGas'
  )
    return false;
  return [
    { cause: error.error, payload: error.payload },
    { cause: error.info?.error, payload: error.info?.payload },
  ].some(
    ({ cause, payload }) =>
      cause?.name !== 'AbortError' &&
      unsupportedCode(cause?.code) &&
      payload?.method === 'eth_maxPriorityFeePerGas' &&
      Array.isArray(payload.params) &&
      payload.params.length === 0
  );
}

/**
 * No signer, transport, network registry or provider implementation is imported.
 * Reads are serialized and guarded; RPC failures never become fabricated fees.
 */
export async function getEvmFeeData(
  reader: EvmFeeReader,
  options: EvmFeeOptions = {}
): Promise<EvmFeeData> {
  const signals = [options.signal, reader.signal].filter(
    (signal): signal is AbortSignal => signal !== undefined
  );
  const assertCurrent = options.assertCurrent;
  const check = () => {
    if (signals.some((signal) => signal.aborted)) {
      const error = new Error('EVM fee discovery aborted');
      error.name = 'AbortError';
      throw error;
    }
    if (assertCurrent) {
      const result: unknown = assertCurrent();
      if (result !== undefined) {
        // A void callback type also accepts async functions. Never await one.
        void Promise.resolve(result).catch(() => undefined);
        throw new Error('EVM fee guard must be synchronous');
      }
    }
    if (signals.some((signal) => signal.aborted)) {
      const error = new Error('EVM fee discovery aborted');
      error.name = 'AbortError';
      throw error;
    }
  };
  check();
  const minPriorityFee =
    options.minPriorityFee == null
      ? undefined
      : parseEvmFeeQuantity(options.minPriorityFee, 'minimum priority fee');
  // Retain the existing zero/absent override behavior.
  const multiplier = options.feeMultiplier || 250;
  if (!Number.isSafeInteger(multiplier) || multiplier < 1)
    throw new Error('Invalid fee multiplier');
  const getGasPrice = reader.getGasPrice.bind(reader);
  const getBlock = reader.getBlock.bind(reader);
  const send = reader.send.bind(reader);
  const read = async <T>(operation: () => Promise<T>): Promise<T> => {
    check();
    let cleanup = () => undefined;
    try {
      const interrupted = new Promise<never>((_, reject) => {
        const abort = () => {
          const error = new Error('EVM fee discovery aborted');
          error.name = 'AbortError';
          reject(error);
        };
        signals.forEach((signal) =>
          signal.addEventListener('abort', abort, { once: true })
        );
        cleanup = () => {
          signals.forEach((signal) =>
            signal.removeEventListener('abort', abort)
          );
          return undefined;
        };
      });
      // No asynchronous gap between the current-owner check and dispatch.
      const result = await Promise.race([operation(), interrupted]);
      check();
      return result;
    } catch (error) {
      check();
      throw error;
    } finally {
      cleanup();
    }
  };

  const gasPrice = parseEvmFeeQuantity(await read(getGasPrice), 'gas price');
  const block = await read(() => getBlock('latest'));
  if (!block) throw new Error('Block not found');
  if (typeof block !== 'object' || Array.isArray(block))
    throw new Error('Invalid block');
  const rawBaseFee = block.baseFeePerGas;
  if (rawBaseFee == null) {
    check();
    return Object.freeze({
      gasPrice,
      maxFeePerGas: 0n,
      maxPriorityFeePerGas: 0n,
    });
  }
  const baseFeePerGas = parseEvmFeeQuantity(rawBaseFee, 'base fee');
  let maxPriorityFeePerGas: bigint;
  try {
    maxPriorityFeePerGas = parseEvmFeeQuantity(
      await read(() => send('eth_maxPriorityFeePerGas', [])),
      'priority fee'
    );
  } catch (error) {
    check();
    if (
      error?.code === 'SYSWEB3_RPC_RESPONSE_INVALID' ||
      error?.name === 'AbortError' ||
      !unsupportedPriorityMethod(error)
    )
      throw error;
    const history = await read(() =>
      send('eth_feeHistory', ['0x5', 'latest', [25, 50, 75]])
    );
    const rewards = (history as { reward?: unknown } | null)?.reward;
    if (!Array.isArray(rewards) || rewards.length < 1 || rewards.length > 5)
      throw new Error('Priority fee history unavailable');
    const recentFees = rewards
      .map((reward: unknown) => {
        if (!Array.isArray(reward) || reward.length !== 3)
          throw new Error('Invalid priority fee history');
        const parsed = reward.map((value) =>
          parseEvmFeeQuantity(value, 'priority fee history')
        );
        return parsed[1];
      })
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    maxPriorityFeePerGas =
      (recentFees[Math.floor(recentFees.length / 2)] * 150n) / 100n;
  }
  if (minPriorityFee !== undefined && maxPriorityFeePerGas < minPriorityFee)
    maxPriorityFeePerGas = minPriorityFee;
  const baseline = (gasPrice * 120n) / 100n;
  const calculated =
    (baseFeePerGas * BigInt(multiplier)) / 100n + maxPriorityFeePerGas;
  let maxFeePerGas = calculated > baseline ? calculated : baseline;
  const minimum = (maxPriorityFeePerGas * 120n) / 100n;
  if (maxFeePerGas < minimum) maxFeePerGas = minimum;
  if (maxFeePerGas === 0n) throw new Error('Invalid EIP-1559 maximum fee');
  parseEvmFeeQuantity(maxFeePerGas, 'maximum fee');
  parseEvmFeeQuantity(maxPriorityFeePerGas, 'priority fee');
  check();
  return Object.freeze({
    gasPrice,
    baseFeePerGas,
    maxFeePerGas,
    maxPriorityFeePerGas,
  });
}
