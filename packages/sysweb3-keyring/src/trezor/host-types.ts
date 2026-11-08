import type {
  ConnectDynamicSettings,
  TrezorConnectPublicAPI,
} from '@trezor/connect-webextension';

export const TREZOR_METHODS = [
  'getFeatures',
  'getAccountInfo',
  'ethereumGetAddress',
  'ethereumGetPublicKey',
  'getPublicKey',
  'getAddress',
  'signMessage',
  'ethereumSignMessage',
  'ethereumSignTypedData',
  'verifyMessage',
  'ethereumVerifyMessage',
  'ethereumSignTransaction',
  'signTransaction',
] as const;

export type TrezorMethod = (typeof TREZOR_METHODS)[number];
export type TrezorCalls = Pick<
  TrezorConnectPublicAPI<ConnectDynamicSettings>,
  TrezorMethod
>;

type GuardedCall<Call> = Call extends {
  (...args: infer A): infer R;
  (...args: infer B): infer S;
  (...args: infer C): infer T;
}
  ? {
      (assertCurrent: () => void, ...args: A): R;
      (assertCurrent: () => void, ...args: B): S;
      (assertCurrent: () => void, ...args: C): T;
    }
  : never;

/** Recheck after asynchronous preparation and immediately before device I/O. */
export type TrezorHostCalls = {
  [Method in TrezorMethod]: GuardedCall<TrezorCalls[Method]>;
};

/** One explicitly owned client. This contract imports no platform runtime. */
export type TrezorHost = TrezorHostCalls & {
  /** Check after asynchronous preparation and immediately before prompting. */
  init(assertCurrent: () => void): Promise<void>;
  /** Retire this host's client according to its platform cleanup requirements. */
  dispose(pendingCalls: readonly Promise<unknown>[]): Promise<void>;
};
