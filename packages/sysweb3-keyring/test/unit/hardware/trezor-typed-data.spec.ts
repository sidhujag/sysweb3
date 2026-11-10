/* eslint-disable camelcase -- Trezor Connect wire protocol field names. */
import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';
import { concat, keccak256, recoverAddress, Wallet } from 'ethers';

import { TrezorKeyring } from '../../../src/trezor';
import { createTrezorConnection } from '../../../src/trezor/connect';
import { TREZOR_METHODS } from '../../../src/trezor/host-types';

import type { LedgerTypedData } from '../../../src/ledger/host-types';
import type { TrezorHost } from '../../../src/trezor/host-types';

jest.unmock('../../../src/trezor/connect');

const wallet = new Wallet('0x' + '11'.repeat(32));
const another = new Wallet('0x' + '22'.repeat(32));
const typed = (): LedgerTypedData => ({
  types: {
    EIP712Domain: [{ name: 'name', type: 'string' }],
    Login: [{ name: 'text', type: 'string' }],
  },
  domain: { name: 'Reviewed app' },
  primaryType: 'Login',
  message: { text: 'Sign in' },
});
const alternative = (): LedgerTypedData => ({
  types: {
    EIP712Domain: [{ name: 'name', type: 'string' }],
    Permit: [{ name: 'spender', type: 'address' }],
  },
  domain: { name: 'Another authorization' },
  primaryType: 'Permit',
  message: { spender: another.address },
});
const digest = (
  data: LedgerTypedData,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4
) => `0x${TypedDataUtils.eip712Hash(data as any, version).toString('hex')}`;
const hashes = (
  data: LedgerTypedData,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4
) => ({
  domain_separator_hash: TypedDataUtils.eip712DomainHash(
    data as any,
    version
  ).toString('hex'),
  message_hash: TypedDataUtils.hashStruct(
    data.primaryType,
    data.message,
    data.types,
    version
  ).toString('hex'),
});
const fixture = () => {
  const controller = new AbortController();
  const owner = {
    signal: controller.signal,
    assertCurrent() {
      if (controller.signal.aborted) throw Error('Owner changed');
    },
  };
  // Exercise the Model One hash-signing protocol through the real SDK connection.
  const sign = jest.fn(async (check: () => void, request: any) => {
    check();
    const hash = keccak256(
      concat([
        '0x1901',
        `0x${request.domain_separator_hash}`,
        `0x${request.message_hash}`,
      ])
    );
    return {
      success: true,
      payload: {
        address: wallet.address,
        signature: wallet.signingKey.sign(hash).serialized,
      },
    };
  });
  const host = {
    ...Object.fromEntries(
      TREZOR_METHODS.map((method) => [
        method,
        jest.fn(async (check: () => void) => {
          check();
          return { success: true, payload: {} };
        }),
      ])
    ),
    ethereumSignTypedData: sign,
    init: jest.fn(async (check: () => void) => check()),
    dispose: jest.fn(async (pending: readonly Promise<unknown>[]) => {
      await Promise.allSettled(pending);
    }),
  } as unknown as TrezorHost;
  const ring = new TrezorKeyring(createTrezorConnection(host));
  return { ring, sign, owner, controller };
};
const execute = async (
  f: ReturnType<typeof fixture>,
  data: LedgerTypedData,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4
) => {
  const result = f.ring
    .signTypedData(
      { address: wallet.address, index: 2, data, version },
      f.owner
    )
    .then(
      (value) => ({ value }),
      (error) => ({ error })
    );
  await jest.advanceTimersByTimeAsync(12000);
  return result;
};
beforeEach(() => jest.useFakeTimers());
afterEach(() => jest.useRealTimers());

for (const version of [
  SignTypedDataVersion.V3,
  SignTypedDataVersion.V4,
] as const) {
  test(`${version} accepts a genuine Model One signature for the reviewed data`, async () => {
    const f = fixture(),
      data = typed();
    try {
      const result = await execute(f, data, version);
      expect(result).toEqual({ value: expect.any(String) });
      if ('value' in result)
        expect(recoverAddress(digest(data, version), result.value)).toBe(
          wallet.address
        );
      expect(f.sign).toHaveBeenCalledTimes(1);
    } finally {
      await f.ring.retire();
    }
  });
  for (const fields of ['domain', 'message', 'both'] as const)
    test(`${version} caller ${fields} hash fields cannot override the reviewed authorization`, async () => {
      const f = fixture(),
        data = typed(),
        injected = hashes(alternative(), version);
      const input = {
        ...data,
        ...(fields === 'message'
          ? {}
          : { domain_separator_hash: injected.domain_separator_hash }),
        ...(fields === 'domain' ? {} : { message_hash: injected.message_hash }),
        path: 'untrusted',
        metamask_v4_compat: false,
      };
      try {
        const result = await execute(f, input, version);
        expect(result).toEqual({ value: expect.any(String) });
        if ('value' in result)
          expect(recoverAddress(digest(data, version), result.value)).toBe(
            wallet.address
          );
        const sent = f.sign.mock.calls[0][1];
        expect(sent.domain_separator_hash).toBe(
          hashes(data, version).domain_separator_hash
        );
        expect(sent.message_hash).toBe(hashes(data, version).message_hash);
        expect(sent.path).toBe("m/44'/60'/0'/0/2");
        expect(sent.metamask_v4_compat).toBe(
          version === SignTypedDataVersion.V4
        );
        expect(Object.keys(sent.data).sort()).toEqual([
          'domain',
          'message',
          'primaryType',
          'types',
        ]);
      } finally {
        await f.ring.retire();
      }
    });
  for (const response of ['other-data', 'other-key', 'malformed'] as const)
    test(`${version} rejects ${response} signature despite the claimed expected address without a second prompt`, async () => {
      const f = fixture();
      f.sign.mockImplementationOnce(async () => ({
        success: true,
        payload: {
          address: wallet.address,
          signature:
            response === 'malformed'
              ? '0x12'
              : response === 'other-key'
              ? another.signingKey.sign(digest(typed(), version)).serialized
              : wallet.signingKey.sign(digest(alternative(), version))
                  .serialized,
        },
      }));
      try {
        expect(await execute(f, typed(), version)).toEqual({
          error: expect.any(Error),
        });
        expect(f.sign).toHaveBeenCalledTimes(1);
      } finally {
        await f.ring.retire();
      }
    });
}

test('domain-only primary type cannot acquire a caller-supplied message hash', async () => {
  const f = fixture(),
    data = { ...typed(), primaryType: 'EIP712Domain', message: {} };
  try {
    const result = await execute(
      f,
      { ...data, message_hash: 'ab'.repeat(32) } as LedgerTypedData,
      SignTypedDataVersion.V4
    );
    expect(result).toEqual({ value: expect.any(String) });
    if ('value' in result)
      expect(
        recoverAddress(digest(data, SignTypedDataVersion.V4), result.value)
      ).toBe(wallet.address);
    expect(f.sign.mock.calls[0][1].message_hash).toBe('');
  } finally {
    await f.ring.retire();
  }
});

test('normalizes empty defaults before hashing and device dispatch', async () => {
  const f = fixture();
  const input = {
    types: { Empty: [] },
    primaryType: 'Empty',
  } as unknown as LedgerTypedData;
  const expected = {
    ...input,
    types: { ...input.types, EIP712Domain: [] },
    domain: {},
    message: {},
  };
  try {
    const result = await execute(f, input, SignTypedDataVersion.V4);
    expect(result).toEqual({ value: expect.any(String) });
    if ('value' in result)
      expect(
        recoverAddress(digest(expected, SignTypedDataVersion.V4), result.value)
      ).toBe(wallet.address);
    expect(f.sign).toHaveBeenCalledTimes(1);
  } finally {
    await f.ring.retire();
  }
});

test('valid V4 arrays and normalized bigint/bytes retain their signing meaning', async () => {
  const f = fixture();
  const input = {
    ...typed(),
    types: {
      ...typed().types,
      Login: [
        { name: 'amounts', type: 'uint256[]' },
        { name: 'blob', type: 'bytes' },
      ],
    },
    message: { amounts: [1n, 2n], blob: new Uint8Array([1, 2]) },
  };
  const expected = {
    ...input,
    message: { amounts: ['1', '2'], blob: '0x0102' },
  };
  try {
    const result = await execute(f, input, SignTypedDataVersion.V4);
    expect(result).toEqual({ value: expect.any(String) });
    if ('value' in result)
      expect(
        recoverAddress(digest(expected, SignTypedDataVersion.V4), result.value)
      ).toBe(wallet.address);
  } finally {
    await f.ring.retire();
  }
});

test('V3 arrays remain unsupported and fail before device dispatch', async () => {
  const f = fixture();
  try {
    const data = {
      ...typed(),
      types: {
        ...typed().types,
        Login: [{ name: 'values', type: 'uint256[]' }],
      },
      message: { values: ['1'] },
    };
    expect(await execute(f, data, SignTypedDataVersion.V3)).toEqual({
      error: expect.any(Error),
    });
    expect(f.sign).not.toHaveBeenCalled();
  } finally {
    await f.ring.retire();
  }
});

test('cancelled authority cannot release a genuine late device signature', async () => {
  const f = fixture(),
    original = f.sign.getMockImplementation()!;
  f.sign.mockImplementationOnce(async (check, request) => {
    const response = await original(check, request);
    f.controller.abort();
    return response;
  });
  try {
    expect(await execute(f, typed(), SignTypedDataVersion.V4)).toEqual({
      error: expect.objectContaining({ code: 'HARDWARE_REQUEST_CANCELLED' }),
    });
    expect(f.sign).toHaveBeenCalledTimes(1);
  } finally {
    await f.ring.retire();
  }
});
