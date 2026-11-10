import { SignTypedDataVersion, TypedDataUtils } from '@metamask/eth-sig-util';
import { Wallet } from 'ethers';

import { HostKeyring } from '../../../src/host-keyring';
import {
  createKeyringHost,
  INetworkType,
  KeyringAccountType,
} from '../../../src/software';

import type { KeyringStoragePort } from '../../../src/software';

const mnemonic =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const password = 'hardware public operation fixture';
const wallet = new Wallet('0x' + '11'.repeat(32));
const current = () => undefined;
const typedData = {
  domain: {},
  types: { EIP712Domain: [], Note: [{ name: 'text', type: 'string' }] },
  primaryType: 'Note',
  message: { text: 'approved' },
};
const typedSignature = wallet.signingKey.sign(
  `0x${TypedDataUtils.eip712Hash(typedData, SignTypedDataVersion.V4).toString(
    'hex'
  )}`
).serialized;
const noSecrets = (ring: HostKeyring<any, any>) => {
  expect(ring.isUnlocked()).toBe(false);
  expect((ring as any).sessionPassword).toBeNull();
  expect((ring as any).sessionMnemonic).toBeNull();
};
async function fixture(type: KeyringAccountType, available = true) {
  const records = new Map<string, unknown>();
  const storage: KeyringStoragePort = {
    get: async (key) => records.get(key),
    set: async (key, value) => {
      records.set(key, value);
    },
    deleteItem: async (key) => {
      records.delete(key);
    },
    createManyIfAbsent: async (items) => {
      if (Object.keys(items).some((key) => records.has(key))) return false;
      Object.entries(items).forEach(([key, value]) => records.set(key, value));
      return true;
    },
  };
  const state: any = {
    activeAccount: { id: 0, type: KeyringAccountType.HDAccount },
    activeNetwork: {
      kind: INetworkType.Ethereum,
      chainId: 1,
      slip44: 60,
      label: 'Ethereum',
      currency: 'ETH',
      url: 'https://offline.invalid',
    },
    accounts: {
      HDAccount: {},
      Imported: {},
      Ledger: {},
      Trezor: {},
      SmartAccount: {},
    },
  };
  const personal = jest.fn(async () => {
    return type === KeyringAccountType.Trezor
      ? { signature: await wallet.signMessage('approved') }
      : wallet.signMessage('approved');
  });
  const typed = jest.fn(async () => typedSignature);
  const ring = new HostKeyring(
    createKeyringHost(storage),
    { captureEvmSubmission: null, secretLifetime: 'operation' },
    () => ({
      ledgerSigner: available
        ? ({
            evm: { signPersonalMessage: personal, signTypedData: typed },
          } as any)
        : undefined,
      trezorSigner: available
        ? ({ signMessage: personal, signTypedData: typed } as any)
        : undefined,
      syscoinHardwareSigners: {},
    })
  );
  ring.setVaultStateGetter(() => state);
  state.accounts.HDAccount[0] = await ring.initializeWalletSecurely(
    mnemonic,
    password
  );
  if (type !== KeyringAccountType.HDAccount) {
    state.accounts[type][2] = {
      id: 2,
      address: wallet.address,
      xpub: wallet.signingKey.compressedPublicKey,
      isLedgerWallet: type === KeyringAccountType.Ledger,
      isTrezorWallet: type === KeyringAccountType.Trezor,
    };
    state.activeAccount = { id: 2, type };
  }
  return { ring, state, personal, typed };
}

for (const type of [KeyringAccountType.Ledger, KeyringAccountType.Trezor]) {
  it(`${type} personal and typed messages use public ownership without software secrets`, async () => {
    const f = await fixture(type);
    try {
      noSecrets(f.ring);
      const authority = {
        assertCurrent: current,
        signal: new AbortController().signal,
      };
      expect(
        await f.ring.ethereumTransaction.signPersonalMessage(
          ['approved', wallet.address],
          authority
        )
      ).toBe(await wallet.signMessage('approved'));
      expect(
        await f.ring.ethereumTransaction.signTypedData(
          wallet.address,
          typedData,
          SignTypedDataVersion.V4,
          authority
        )
      ).toBe(typedSignature);
      expect(f.personal).toHaveBeenCalledTimes(1);
      expect(f.typed).toHaveBeenCalledTimes(1);
      noSecrets(f.ring);
    } finally {
      await f.ring.destroy();
    }
  });
  for (const change of ['account', 'network', 'lock'] as const) {
    it(`${type} refuses a held message result after ${change}`, async () => {
      const f = await fixture(type);
      let release!: () => void;
      const held = new Promise<void>((resolve) => {
        release = resolve;
      });
      let called!: () => void;
      const entered = new Promise<void>((resolve) => {
        called = resolve;
      });
      f.personal.mockImplementationOnce(async () => {
        called();
        await held;
        return type === KeyringAccountType.Trezor
          ? { signature: await wallet.signMessage('approved') }
          : wallet.signMessage('approved');
      });
      try {
        const work = f.ring.ethereumTransaction.signPersonalMessage(
          ['approved', wallet.address],
          { assertCurrent: current, signal: new AbortController().signal }
        );
        const rejected = expect(work).rejects.toThrow();
        await entered;
        if (change === 'account')
          f.state.activeAccount = { id: 0, type: KeyringAccountType.HDAccount };
        if (change === 'network')
          f.state.activeNetwork = { ...f.state.activeNetwork, chainId: 2 };
        if (change === 'lock') await f.ring.lockWallet();
        release();
        await rejected;
        noSecrets(f.ring);
      } finally {
        release();
        await f.ring.destroy();
      }
    });
  }
  it(`${type} requires an actual device capability even with valid public ownership`, async () => {
    const f = await fixture(type, false);
    try {
      await expect(
        f.ring.ethereumTransaction.signPersonalMessage(
          ['approved', wallet.address],
          { assertCurrent: current, signal: new AbortController().signal }
        )
      ).rejects.toMatchObject({ code: 'HARDWARE_SIGNER_UNAVAILABLE' });
      noSecrets(f.ring);
    } finally {
      await f.ring.destroy();
    }
  });
}

it('software message signing remains forbidden outside the secret operation', async () => {
  const f = await fixture(KeyringAccountType.HDAccount);
  try {
    const authority = {
      assertCurrent: current,
      signal: new AbortController().signal,
    };
    const address = f.state.accounts.HDAccount[0].address;
    await expect(
      f.ring.ethereumTransaction.signPersonalMessage(
        ['approved', address],
        authority
      )
    ).rejects.toThrow();
    const result = await f.ring.withSecretOperation(
      {
        async withSecret(check, consume) {
          check();
          await consume(password);
          check();
        },
      },
      authority,
      () =>
        f.ring.ethereumTransaction.signPersonalMessage(
          ['approved', address],
          authority
        )
    );
    expect(typeof result).toBe('string');
    expect(result).toMatch(/^0x[0-9a-f]+$/);
    noSecrets(f.ring);
    expect(f.personal).not.toHaveBeenCalled();
  } finally {
    await f.ring.destroy();
  }
});
