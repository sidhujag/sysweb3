import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';
import { hashMessage, Transaction, Wallet } from 'ethers';

import { HardwareWalletManager } from '../../../src/hardware-wallet-manager';
import { KeyringManager } from '../../../src/keyring-manager';
import { LedgerKeyring } from '../../../src/ledger';
import { createTestKeyringHost } from '../../helpers/keyring-host';

import type { LedgerHost } from '../../../src/ledger/host-types';

const messageAuthority = () => ({
  assertCurrent: () => undefined,
  signal: new AbortController().signal,
});

const hostFixture = (): LedgerHost => ({
  connect: jest.fn(async () => undefined),
  disconnect: jest.fn(async () => undefined),
  retire: jest.fn(async () => () => undefined),
  getStatus: () => ({ connected: true }),
  evm: {} as LedgerHost['evm'],
  utxo: {} as LedgerHost['utxo'],
});

test('rejects separate manager and host injection before opening either device authority', () => {
  const host = hostFixture();
  const manager = { destroy: jest.fn() } as unknown as HardwareWalletManager;
  expect(
    () =>
      new KeyringManager(createTestKeyringHost(), {
        hardwareManager: manager,
        ledgerHost: host,
      } as any)
  ).toThrow('Supply exactly one hardware manager or Ledger host');
  expect(host.connect).not.toHaveBeenCalled();
  expect(host.disconnect).not.toHaveBeenCalled();
  expect(manager.destroy).not.toHaveBeenCalled();
});

test('requires durable EVM admission before constructing a browser keyring', () => {
  const ledgerHost = hostFixture();
  expect(() =>
    Reflect.construct(KeyringManager, [createTestKeyringHost(), { ledgerHost }])
  ).toThrow('Browser keyring requires durable EVM submission');
  expect(ledgerHost.connect).not.toHaveBeenCalled();
});

test('requires explicit Trezor capabilities for a browser keyring', () => {
  const ledgerHost = hostFixture();
  expect(() =>
    Reflect.construct(KeyringManager, [
      createTestKeyringHost(),
      {
        ledgerHost,
        captureEvmSubmission: () => undefined,
      },
    ])
  ).toThrow('Trezor requires explicit host capabilities');
  expect(ledgerHost.connect).not.toHaveBeenCalled();
});

test('host-only injection binds the facade and its manager to the same host', async () => {
  const host = hostFixture();
  const keyring = new KeyringManager(createTestKeyringHost(), {
    trezorHost: jest.requireMock('@trezor/connect-webextension'),
    captureEvmSubmission: () => {
      throw new Error('EVM submission is outside this fixture');
    },
    ledgerHost: host,
  });
  try {
    await expect(
      keyring.ledgerSigner.ensureConnection()
    ).resolves.toBeUndefined();
    expect(keyring.ledgerSigner.getStatus().connected).toBe(true);
    const manager = (keyring.ledgerSigner as any).sharedHardwareWalletManager;
    expect(manager).toBeInstanceOf(HardwareWalletManager);
    expect(manager.isConnected('ledger')).toBe(true);
  } finally {
    await keyring.destroy();
  }
  expect(host.disconnect).toHaveBeenCalled();
});

const signingWallet = new Wallet(`0x${'11'.repeat(32)}`);
const otherWallet = new Wallet(`0x${'22'.repeat(32)}`);
const tx = (value = 1, chainId = 1) =>
  Transaction.from({
    type: 2,
    chainId,
    nonce: 3,
    gasLimit: 21000,
    maxFeePerGas: 10,
    maxPriorityFeePerGas: 1,
    to: otherWallet.address,
    value,
  });
const fields = (
  signature: ReturnType<typeof signingWallet.signingKey.sign>
) => ({
  r: signature.r.slice(2),
  s: signature.s.slice(2),
  v: signature.v.toString(16),
});
const typed = () => ({
  domain: { name: 'Public fixture', chainId: 1 },
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'chainId', type: 'uint256' },
    ],
    Message: [{ name: 'value', type: 'string' }],
  },
  primaryType: 'Message',
  message: { value: 'approved' },
});
const typedHash = (
  data: any,
  version: SignTypedDataVersion.V3 | SignTypedDataVersion.V4
) => `0x${TypedDataUtils.eip712Hash(data, version).toString('hex')}`;
const cryptoHost = () => {
  const host = hostFixture();
  host.evm = {
    getAddress: jest.fn(async () => ({
      address: signingWallet.address,
      publicKey: signingWallet.signingKey.publicKey,
    })),
    signTransaction: jest.fn(async ({ unsignedTxHex }) =>
      fields(
        signingWallet.signingKey.sign(
          Transaction.from(`0x${unsignedTxHex}`).unsignedHash
        )
      )
    ),
    signPersonalMessage: jest.fn(async ({ messageHex }) =>
      signingWallet.signMessage(Buffer.from(messageHex, 'hex'))
    ),
    signTypedData: jest.fn(
      async ({ data, version }) =>
        signingWallet.signingKey.sign(
          typedHash(
            data,
            version as SignTypedDataVersion.V3 | SignTypedDataVersion.V4
          )
        ).serialized
    ),
  };
  return { host, ledger: new LedgerKeyring(undefined, host) };
};

test('rejects a direct Ledger transaction without explicit approval before connection', async () => {
  const { host, ledger } = cryptoHost();
  host.getStatus = () => ({ connected: false });
  await expect(
    Reflect.apply(ledger.evm.signEVMTransaction, undefined, [
      {
        accountIndex: 0,
        expectedAddress: signingWallet.address,
        rawTx: tx().unsignedSerialized,
      },
    ])
  ).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(host.connect).not.toHaveBeenCalled();
  expect(host.evm.signTransaction).not.toHaveBeenCalled();
});

test('does not dispatch an EVM signer after the review changes during Ledger connection', async () => {
  const { host, ledger } = cryptoHost();
  host.getStatus = () => ({ connected: false });
  let release!: () => void;
  (host.connect as jest.Mock).mockImplementationOnce(
    () =>
      new Promise<void>((resolve) => {
        release = resolve;
      })
  );
  let current = true;
  const pending = ledger.evm.signEVMTransaction(
    {
      accountIndex: 0,
      expectedAddress: signingWallet.address,
      rawTx: tx().unsignedSerialized,
    },
    {
      signal: new AbortController().signal,
      assertCurrent() {
        if (!current) throw new Error('Approval expired');
      },
    }
  );
  current = false;
  release();
  await expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
    transactionNotBroadcast: true,
  });
  expect(host.evm.signTransaction).not.toHaveBeenCalled();
});

test('validates address/public-key equality at the authority boundary', async () => {
  const { host, ledger } = cryptoHost();
  await expect(
    ledger.evm.getEvmAddressAndPubKey({ accountIndex: 0 })
  ).resolves.toEqual({
    address: signingWallet.address,
    publicKey: signingWallet.signingKey.publicKey.slice(2),
  });
  (host.evm.getAddress as jest.Mock).mockResolvedValueOnce({
    address: signingWallet.address,
    publicKey: otherWallet.signingKey.publicKey,
  });
  await expect(
    ledger.evm.getEvmAddressAndPubKey({ accountIndex: 0 })
  ).rejects.toMatchObject({ code: 'LEDGER_INVALID_RESPONSE' });
});

test.each(['valid', 'wrong-account', 'different-transaction', 'wrong-chain-v'])(
  'validates the approved transaction signature (%s)',
  async (response) => {
    const { host, ledger } = cryptoHost();
    const approved = tx();
    if (response === 'wrong-account')
      (host.evm.signTransaction as jest.Mock).mockResolvedValueOnce(
        fields(otherWallet.signingKey.sign(approved.unsignedHash))
      );
    if (response === 'different-transaction')
      (host.evm.signTransaction as jest.Mock).mockResolvedValueOnce(
        fields(signingWallet.signingKey.sign(tx(2).unsignedHash))
      );
    if (response === 'wrong-chain-v') {
      const signature = fields(
        signingWallet.signingKey.sign(approved.unsignedHash)
      );
      signature.v = (Number.parseInt(signature.v, 16) + 12).toString(16); // EIP155 chain 2, approved chain 1.
      (host.evm.signTransaction as jest.Mock).mockResolvedValueOnce(signature);
    }
    const pending = ledger.evm.signEVMTransaction(
      {
        accountIndex: 0,
        expectedAddress: signingWallet.address,
        rawTx: approved.unsignedSerialized,
      },
      {
        signal: new AbortController().signal,
        assertCurrent: () => undefined,
      }
    );
    if (response === 'valid')
      await expect(pending).resolves.toEqual(
        fields(signingWallet.signingKey.sign(approved.unsignedHash))
      );
    else
      await expect(pending).rejects.toMatchObject({
        code: 'LEDGER_INVALID_SIGNATURE',
      });
  }
);

test.each(['', '00ff80', Buffer.from('Pali 💚').toString('hex')])(
  'verifies exact personal-message bytes %s',
  async (message) => {
    const { ledger } = cryptoHost();
    await expect(
      ledger.evm.signPersonalMessage(
        {
          accountIndex: 0,
          expectedAddress: signingWallet.address,
          message,
        },
        messageAuthority()
      )
    ).resolves.toBe(
      await signingWallet.signMessage(Buffer.from(message, 'hex'))
    );
  }
);

test.each(['wrong-account', 'wrong-bytes'])(
  'rejects a personal signature for %s',
  async (response) => {
    const { host, ledger } = cryptoHost();
    (host.evm.signPersonalMessage as jest.Mock).mockResolvedValueOnce(
      (response === 'wrong-account'
        ? otherWallet
        : signingWallet
      ).signingKey.sign(
        hashMessage(
          Buffer.from(response === 'wrong-bytes' ? '00' : 'ff', 'hex')
        )
      ).serialized
    );
    await expect(
      ledger.evm.signPersonalMessage(
        {
          accountIndex: 0,
          expectedAddress: signingWallet.address,
          message: 'ff',
        },
        messageAuthority()
      )
    ).rejects.toMatchObject({ code: 'LEDGER_INVALID_SIGNATURE' });
  }
);

test.each([SignTypedDataVersion.V3, SignTypedDataVersion.V4])(
  'validates %s typed-data signature and rejects a different payload',
  async (version) => {
    const { host, ledger } = cryptoHost();
    const data = typed();
    await expect(
      ledger.evm.signTypedData(
        {
          accountIndex: 0,
          expectedAddress: signingWallet.address,
          version,
          data,
        },
        messageAuthority()
      )
    ).resolves.toBe(
      signingWallet.signingKey.sign(typedHash(data, version)).serialized
    );
    (host.evm.signTypedData as jest.Mock).mockResolvedValueOnce(
      signingWallet.signingKey.sign(
        typedHash({ ...data, message: { value: 'different' } }, version)
      ).serialized
    );
    await expect(
      ledger.evm.signTypedData(
        {
          accountIndex: 0,
          expectedAddress: signingWallet.address,
          version,
          data,
        },
        messageAuthority()
      )
    ).rejects.toMatchObject({ code: 'LEDGER_INVALID_SIGNATURE' });
  }
);

test('captures typed data before pending connection and exposes no mutable approval object', async () => {
  const { host, ledger } = cryptoHost();
  let complete!: () => void;
  host.getStatus = () => ({ connected: false });
  host.connect = jest.fn(
    () =>
      new Promise<void>((resolve) => {
        complete = resolve;
      })
  );
  const data = typed();
  const pending = ledger.evm.signTypedData(
    {
      accountIndex: 0,
      expectedAddress: signingWallet.address,
      version: SignTypedDataVersion.V4,
      data,
    },
    messageAuthority()
  );
  data.message.value = 'changed after request';
  complete();
  await pending;
  const approved = (host.evm.signTypedData as jest.Mock).mock.calls[0][0].data;
  expect(approved.message.value).toBe('approved');
  expect(Object.isFrozen(approved.message)).toBe(true);
});

test.each(['signPsbt', 'signUtxoMessage'] as const)(
  'captures %s request fields before a pending connection',
  async (method) => {
    const host = hostFixture();
    const ledger = new LedgerKeyring(undefined, host);
    let complete!: () => void;
    host.getStatus = () => ({ connected: false });
    host.connect = jest.fn(
      () =>
        new Promise<void>((resolve) => {
          complete = resolve;
        })
    );
    const request = {
      currency: 'tSYS',
      slip44: 1,
      accountIndex: 0,
      accountXpub: 'approved account xpub',
      ...(method === 'signPsbt'
        ? { psbtBase64: 'approved psbt' }
        : { message: 'approved message', addressIndex: 2, change: false }),
    };
    const expected = { ...request };
    const sign: jest.Mock = jest.fn(async () => {
      return method === 'signPsbt'
        ? { fingerprint: '01020304', signatures: [] }
        : 'signature';
    });
    if (method === 'signPsbt') host.utxo.signPsbt = sign as any;
    else host.utxo.signMessage = sign as any;
    const signal = new AbortController().signal;
    const pending =
      method === 'signPsbt'
        ? ledger.signPsbt(request as any, {
            assertCurrent: () => undefined,
            signal,
          })
        : ledger.signUtxoMessage(request as any, messageAuthority());
    Object.assign(request, {
      currency: 'BTC',
      slip44: 0,
      accountIndex: 1,
      accountXpub: 'replaced account xpub',
      psbtBase64: 'replaced psbt',
      message: 'replaced message',
      addressIndex: 7,
      change: true,
    });
    complete();
    await pending;
    if (method === 'signPsbt')
      expect(sign).toHaveBeenCalledWith(expected, {
        assertCurrent: expect.any(Function),
        signal,
      });
    else
      expect(sign).toHaveBeenCalledWith(
        expected,
        expect.objectContaining({
          assertCurrent: expect.any(Function),
          signal: expect.any(AbortSignal),
        })
      );
    expect(Object.isFrozen(sign.mock.calls[0][0])).toBe(true);
  }
);

test('carries Ledger PSBT approval through a held platform dispatch', async () => {
  const host = hostFixture();
  const ledger = new LedgerKeyring(undefined, host);
  const request = {
    currency: 'tSYS',
    slip44: 1,
    accountIndex: 0,
    accountXpub: 'approved account xpub',
    psbtBase64: 'approved psbt',
  };
  let entered!: () => void, release!: () => void;
  const started = new Promise<void>((resolve) => {
    entered = resolve;
  });
  const held = new Promise<void>((resolve) => {
    release = resolve;
  });
  const post = jest.fn();
  host.utxo.signPsbt = jest.fn(async (_request, owner) => {
    entered();
    await held;
    owner.assertCurrent();
    post();
    return { fingerprint: '01020304', signatures: [] };
  });
  const controller = new AbortController();
  let current = true;
  const pending = ledger.signPsbt(request, {
    signal: controller.signal,
    assertCurrent() {
      if (!current) throw new Error('Approval expired');
    },
  });
  const denied = expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await started;
  current = false;
  release();
  await denied;
  expect(controller.signal.aborted).toBe(false);
  expect(post).not.toHaveBeenCalled();
});

test('discards a queued valid personal signature after synchronous destruction', async () => {
  const { host, ledger } = cryptoHost();
  let complete!: (signature: string) => void;
  (host.evm.signPersonalMessage as jest.Mock).mockReturnValue(
    new Promise<string>((resolve) => {
      complete = resolve;
    })
  );
  const pending = ledger.evm.signPersonalMessage(
    {
      accountIndex: 0,
      expectedAddress: signingWallet.address,
      message: 'ff',
    },
    messageAuthority()
  );
  const rejected = expect(pending).rejects.toMatchObject({
    code: 'HARDWARE_REQUEST_CANCELLED',
  });
  await ledger.destroy();
  complete(
    signingWallet.signingKey.sign(hashMessage(Buffer.from('ff', 'hex')))
      .serialized
  );
  await rejected;
});
