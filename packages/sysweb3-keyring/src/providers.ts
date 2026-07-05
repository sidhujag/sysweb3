import { handleStatusCodeError } from './errorUtils';
import {
  BigNumber,
  JsonRpcProvider,
  normalizeTransactionRequest,
  type Networkish,
} from './ethers-v6';

const TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS = new Set([
  'gasLimit',
  'gasPrice',
  'maxFeePerGas',
  'maxPriorityFeePerGas',
  'value',
]);

const TRANSACTION_RESPONSE_NUMBER_FIELDS = new Set(['chainId']);

const TRANSACTION_RECEIPT_BIG_NUMBER_FIELDS = new Set([
  'blobGasPrice',
  'blobGasUsed',
  'cumulativeGasUsed',
  'effectiveGasPrice',
  'gasPrice',
  'gasUsed',
]);

const defineValue = (target: any, field: string, value: any) => {
  Object.defineProperty(target, field, {
    value,
    configurable: true,
    enumerable: true,
    writable: true,
  });
};

const wrapBigNumberFields = (
  source: any,
  fields: Set<string>,
  omittedFields: Set<string> = fields
) => {
  if (!source) return source;
  const wrapped = Object.create(Object.getPrototypeOf(source));
  const descriptors = Object.getOwnPropertyDescriptors(source);
  for (const field of omittedFields) {
    delete descriptors[field];
  }
  Object.defineProperties(wrapped, descriptors);

  for (const field of fields) {
    if (source[field] != null) {
      defineValue(wrapped, field, BigNumber.from(source[field]));
    }
  }

  return wrapped;
};

export const wrapTransactionReceipt = (receipt: any) => {
  const wrapped = wrapBigNumberFields(
    receipt,
    TRANSACTION_RECEIPT_BIG_NUMBER_FIELDS
  );
  if (!wrapped) return wrapped;

  return new Proxy(wrapped, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(receipt) : value;
    },
  });
};

export const wrapTransactionResponse = (transaction: any) => {
  if (!transaction) return transaction;
  const omittedFields = new Set([
    ...TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS,
    ...TRANSACTION_RESPONSE_NUMBER_FIELDS,
    'wait',
  ]);
  const wrapped = wrapBigNumberFields(
    transaction,
    TRANSACTION_RESPONSE_BIG_NUMBER_FIELDS,
    omittedFields
  );

  for (const field of TRANSACTION_RESPONSE_NUMBER_FIELDS) {
    if (transaction[field] != null) {
      defineValue(wrapped, field, Number(transaction[field]));
    }
  }

  if (typeof transaction.wait === 'function') {
    defineValue(wrapped, 'wait', async (...args: any[]) =>
      wrapTransactionReceipt(await transaction.wait(...args))
    );
  }

  return new Proxy(wrapped, {
    get(target, property, receiver) {
      const value = Reflect.get(target, property, receiver);
      return typeof value === 'function' ? value.bind(transaction) : value;
    },
  });
};

// Preserve JSON-RPC error details (code, revert data) on thrown errors so
// consumers can decode custom contract errors instead of only seeing
// "execution reverted".
const makeRpcError = (rpcError: {
  code?: number;
  data?: unknown;
  message: string;
}): Error => {
  const error = new Error(rpcError.message) as Error & {
    code?: number;
    data?: unknown;
  };
  if (rpcError.code !== undefined) {
    error.code = rpcError.code;
  }
  if (rpcError.data !== undefined) {
    error.data = rpcError.data;
  }
  return error;
};

class BaseProvider extends JsonRpcProvider {
  private isPossibleGetChainId = true;
  private cooldownTime = 120 * 1000;
  private rateLimit = 30;
  private requestCount = 0;
  private lastRequestTime = 0;
  private currentChainId = '';
  private currentId = 1;
  public isInCooldown = false;
  public errorMessage: any = '';
  public serverHasAnError = false;
  signal: AbortSignal;
  _pendingBatchAggregator: NodeJS.Timer | null;
  _pendingBatch: Array<{
    reject: (error: Error) => void;
    request: { id: number; jsonrpc: '2.0'; method: string; params: Array<any> };
    resolve: (result: any) => void;
  }> | null;

  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish
  ) {
    super(typeof url === 'string' ? url : url?.url, network);
    this.signal = signal;
    this._pendingBatchAggregator = null;
    this._pendingBatch = null;

    this.bindMethods();
  }

  private bindMethods() {
    const proto = Object.getPrototypeOf(this);
    for (const key of Object.getOwnPropertyNames(proto)) {
      if (typeof this[key] === 'function' && key !== 'constructor') {
        this[key] = this[key].bind(this);
      }
    }
  }

  private throttledRequest = <T>(requestFn: () => Promise<T>): Promise<T> => {
    if (!this.canMakeRequest()) {
      return this.cooldown();
    }
    // Execute request immediately without timeout delay
    return requestFn().catch((error) => {
      if (error.name === 'AbortError') {
        console.log('Aborted request', error);
        return Promise.reject(error);
      }
      throw error;
    });
  };
  private canMakeRequest = () => {
    const now = Date.now();
    let elapsedTime = 0;
    if (this.lastRequestTime > 0) {
      elapsedTime = now - this.lastRequestTime;
    }
    if (elapsedTime <= this.cooldownTime && this.serverHasAnError) {
      this.isInCooldown = true;
      return false;
    }

    if (elapsedTime >= this.cooldownTime && this.serverHasAnError) {
      this.requestCount = 0;
      this.serverHasAnError = false;
      this.isInCooldown = true;
      return false; //One last blocked request before cooldown ends
    }

    if (this.requestCount < this.rateLimit || !this.serverHasAnError) {
      this.requestCount++;
      if (elapsedTime > 1000) {
        //Uncomment the console.log to see the request per second
        // console.log(
        //   `Request/sec to Provider(${this.connection.url}): ${this.requestCount}`
        // );
        this.requestCount = 1;
        this.lastRequestTime = now;
      } else if (this.lastRequestTime === 0) {
        this.lastRequestTime = now;
      }
      this.isInCooldown = false;
      return true;
    }
  };

  private cooldown = async () => {
    const now = Date.now();
    const elapsedTime = now - this.lastRequestTime;
    console.error(
      'Cant make request, rpc cooldown is active for the next: ',
      (this.cooldownTime - elapsedTime) / 1000,
      ' seconds'
    );
    throw {
      message: `Cant make request, rpc cooldown is active for the next: ${
        (this.cooldownTime - elapsedTime) / 1000
      } seconds`,
    };
  };

  override send = async (method: string, params: any[]) => {
    if (!this.isPossibleGetChainId && method === 'eth_chainId') {
      return this.currentChainId;
    }

    const headers = {
      'Content-Type': 'application/json',
    };

    const options: RequestInit = {
      method: 'POST',
      headers,
      body: JSON.stringify({
        jsonrpc: '2.0',
        method,
        params,
        id: this.currentId,
      }),
      signal: this.signal,
    };

    const result = await this.throttledRequest(() =>
      fetch(this._getConnection().url, options)
        .then(async (response) => {
          if (!response.ok) {
            let errorBody = {
              error: undefined,
              message: undefined,
            };
            try {
              errorBody = await response.json();
            } catch (error) {
              console.warn('No body in request', error);
            }
            this.errorMessage =
              errorBody.error ||
              errorBody.message ||
              'No message from Provider';
            handleStatusCodeError(response.status, this.errorMessage);
          }
          switch (response.status) {
            case 200:
              return response.json();
            default:
              throw {
                message: `Unexpected HTTP status code: ${response.status}`,
              };
          }
        })
        .then((json) => {
          if (json.error) {
            if (json.error.message.includes('insufficient funds')) {
              console.error({
                errorMessage: json.error.message,
              });
              this.errorMessage = json.error.message;
              throw makeRpcError(json.error);
            }
            this.errorMessage = json.error.message;
            console.log({ requestData: { method, params }, error: json.error });
            console.error({
              errorMessage: json.error.message,
            });
            throw makeRpcError(json.error);
          }
          if (method === 'eth_chainId') {
            this.currentChainId = json.result;
            this.isPossibleGetChainId = false;
          }
          this.currentId++;
          this.serverHasAnError = false;
          return json.result;
        })
    );
    return result;
  };

  async sendBatch(method: string, params: Array<any[]>): Promise<any[]> {
    // Create batch request array
    const requests = params.map((param, index) => ({
      jsonrpc: '2.0',
      id: this.currentId + index,
      method,
      params: param,
    }));

    this.currentId += requests.length;

    const headers = {
      'Content-Type': 'application/json',
    };

    const options: RequestInit = {
      method: 'POST',
      headers,
      body: JSON.stringify(requests),
      signal: this.signal,
    };

    const results = await this.throttledRequest(() =>
      fetch(this._getConnection().url, options)
        .then(async (response) => {
          if (!response.ok) {
            let errorBody = {
              error: undefined,
              message: undefined,
            };
            try {
              errorBody = await response.json();
            } catch (error) {
              console.warn('No body in request', error);
            }
            this.errorMessage =
              errorBody.error ||
              errorBody.message ||
              'No message from Provider';
            handleStatusCodeError(response.status, this.errorMessage);
          }
          return response.json();
        })
        .then((jsonArray) => {
          // Sort results by ID to ensure correct order
          const sortedResults = jsonArray.sort((a: any, b: any) => a.id - b.id);

          // Extract results or throw errors
          return sortedResults.map((json: any) => {
            if (json.error) {
              this.errorMessage = json.error.message;
              console.error({
                errorMessage: json.error.message,
              });
              throw makeRpcError(json.error);
            }
            return json.result;
          });
        })
    );

    return results;
  }

  async getGasPrice() {
    const feeData = await super.getFeeData();
    return BigNumber.from(feeData.gasPrice ?? 0n);
  }

  async getFeeData(): Promise<any> {
    const feeData = await super.getFeeData();
    let maxFeePerGas =
      feeData.maxFeePerGas == null
        ? null
        : BigNumber.from(feeData.maxFeePerGas);
    let maxPriorityFeePerGas =
      feeData.maxPriorityFeePerGas == null
        ? null
        : BigNumber.from(feeData.maxPriorityFeePerGas);

    if (maxFeePerGas == null || maxPriorityFeePerGas == null) {
      const block = await super.getBlock('latest');
      if (block?.baseFeePerGas != null) {
        const baseFeePerGas = BigNumber.from(block.baseFeePerGas);

        if (maxPriorityFeePerGas == null) {
          try {
            maxPriorityFeePerGas = BigNumber.from(
              await super.send('eth_maxPriorityFeePerGas', [])
            );
          } catch {
            maxPriorityFeePerGas =
              feeData.gasPrice == null
                ? BigNumber.from(0)
                : BigNumber.from(feeData.gasPrice);
          }
        }

        maxFeePerGas =
          maxFeePerGas ?? baseFeePerGas.mul(2).add(maxPriorityFeePerGas);
      }
    }

    return {
      gasPrice:
        feeData.gasPrice == null ? null : BigNumber.from(feeData.gasPrice),
      maxFeePerGas,
      maxPriorityFeePerGas,
    };
  }

  async getBalance(address: string, blockTag?: any): Promise<any> {
    return BigNumber.from(await super.getBalance(address, blockTag));
  }

  private async normalizeLegacyCallRequest(transaction: any) {
    const normalized = normalizeTransactionRequest(transaction);

    // Some legacy/non-EIP-1559 RPCs reject a type field on call/estimateGas.
    // Preserve the old provider behavior by stripping explicit type 0 only
    // when the network does not expose EIP-1559 fee fields.
    if (
      normalized?.type === 0 &&
      normalized.maxFeePerGas == null &&
      normalized.maxPriorityFeePerGas == null
    ) {
      const feeData = await super.getFeeData();
      if (
        feeData.maxFeePerGas == null &&
        feeData.maxPriorityFeePerGas == null
      ) {
        delete normalized.type;
      }
    }

    return normalized;
  }

  async call(transaction: any, blockTag?: any): Promise<any> {
    const normalized = await this.normalizeLegacyCallRequest(transaction);
    if (blockTag != null) {
      normalized.blockTag = blockTag;
    }

    return await super.call(normalized);
  }

  async estimateGas(transaction: any): Promise<any> {
    const normalized = await this.normalizeLegacyCallRequest(transaction);

    return BigNumber.from(await super.estimateGas(normalized));
  }

  async getBlock(blockHashOrBlockTag: any): Promise<any> {
    return await super.getBlock(blockHashOrBlockTag);
  }

  async getTransaction(hash: string): Promise<any> {
    return wrapTransactionResponse(await super.getTransaction(hash));
  }

  async sendTransaction(signedTransaction: string) {
    return wrapTransactionResponse(
      await this.broadcastTransaction(signedTransaction)
    );
  }
}

export class CustomJsonRpcProvider extends BaseProvider {
  constructor(
    signal: AbortSignal,
    url?: string | { url: string },
    network?: Networkish
  ) {
    super(signal, url, network);
  }
}
