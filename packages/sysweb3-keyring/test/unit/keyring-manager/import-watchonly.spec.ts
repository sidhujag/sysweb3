import { INetworkType } from '@sidhujag/sysweb3-network';

import { KeyringManager, KeyringAccountType } from '../../../src';
import { FAKE_PASSWORD, PEACE_SEED_PHRASE } from '../../helpers/constants';
import { setupMocks } from '../../helpers/setup';

describe('Watch-only Import - KeyringManager', () => {
  let keyringManager: KeyringManager;
  let mockVaultStateGetter: jest.Mock;
  let currentVaultState: any;

  beforeEach(async () => {
    setupMocks();
    await setupTestVault(FAKE_PASSWORD);
  });

  describe('Single-address watch-only (address)', () => {
    beforeEach(async () => {
      currentVaultState = createMockVaultState({
        activeAccountId: 0,
        activeAccountType: KeyringAccountType.HDAccount,
        networkType: INetworkType.Syscoin,
        chainId: 5700,
      });
      mockVaultStateGetter = jest.fn(() => currentVaultState);

      keyringManager = await KeyringManager.createInitialized(
        PEACE_SEED_PHRASE,
        FAKE_PASSWORD,
        mockVaultStateGetter
      );
    });

    it('imports address as watch-only single-address and blocks derivation', async () => {
      const addr = 'tsys1qtestaddressxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const imported = await (keyringManager as any).importWatchOnly(
        addr,
        'Watch-only'
      );
      expect(imported.isImported).toBe(true);
      // xpub === address marks single-address imported
      expect(imported.xpub).toBe(addr);
      expect(imported.xprv).toBe('');

      // Insert into mock vault and activate
      currentVaultState.accounts[KeyringAccountType.Imported][imported.id] = {
        id: imported.id,
        label: imported.label,
        address: imported.address,
        xpub: imported.xpub,
        xprv: imported.xprv,
        isImported: true,
        isTrezorWallet: false,
        isLedgerWallet: false,
        balances: { syscoin: 0, ethereum: 0 },
        assets: { syscoin: [], ethereum: [] },
      };
      currentVaultState.activeAccount = {
        id: imported.id,
        type: KeyringAccountType.Imported,
      };

      // Guards
      const changeAddr = await keyringManager.getChangeAddress(imported.id);
      expect(changeAddr).toBe(imported.address);
      await expect(
        keyringManager.getPubkey(imported.id, false)
      ).rejects.toThrow(/watch-only|Public key|not available/i);
      await expect(
        keyringManager.getBip32Path(imported.id, false)
      ).rejects.toThrow(/watch-only|BIP32|not available/i);
    });
  });

  describe('XPUB/Descriptor watch-only', () => {
    beforeEach(async () => {
      currentVaultState = createMockVaultState({
        activeAccountId: 0,
        activeAccountType: KeyringAccountType.HDAccount,
        networkType: INetworkType.Syscoin,
        chainId: 57,
      });
      mockVaultStateGetter = jest.fn(() => currentVaultState);

      keyringManager = await KeyringManager.createInitialized(
        PEACE_SEED_PHRASE,
        FAKE_PASSWORD,
        mockVaultStateGetter
      );
    });

    it('imports xpub-like as watch-only and blocks derivation', async () => {
      // Not a real xpub; importWatchOnly should still accept and mark watch-only
      const xpub = 'zpub6testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
      const imported = await (keyringManager as any).importWatchOnly(
        xpub,
        'Watch-only XPUB'
      );
      expect(imported.xprv).toBe('');
      expect(imported.xpub).toBe(xpub);

      currentVaultState.accounts[KeyringAccountType.Imported][imported.id] = {
        id: imported.id,
        label: imported.label,
        address: imported.address,
        xpub: imported.xpub,
        xprv: imported.xprv,
        isImported: true,
        isTrezorWallet: false,
        isLedgerWallet: false,
        balances: { syscoin: 0, ethereum: 0 },
        assets: { syscoin: [], ethereum: [] },
      };
      currentVaultState.activeAccount = {
        id: imported.id,
        type: KeyringAccountType.Imported,
      };

      await expect(
        keyringManager.getPubkey(imported.id, false)
      ).rejects.toThrow(/watch-only|Public key|not available/i);
      await expect(
        keyringManager.getBip32Path(imported.id, false)
      ).rejects.toThrow(/watch-only|BIP32|not available/i);
    });

    it('imports descriptor as watch-only and blocks derivation', async () => {
      const desc = 'wpkh(xpub6testxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx/0/*)';
      const imported = await (keyringManager as any).importWatchOnly(
        desc,
        'Watch-only DESC'
      );
      expect(imported.xprv).toBe('');
      expect(imported.xpub).toBe(desc);

      currentVaultState.accounts[KeyringAccountType.Imported][imported.id] = {
        id: imported.id,
        label: imported.label,
        address: imported.address,
        xpub: imported.xpub,
        xprv: imported.xprv,
        isImported: true,
        isTrezorWallet: false,
        isLedgerWallet: false,
        balances: { syscoin: 0, ethereum: 0 },
        assets: { syscoin: [], ethereum: [] },
      };
      currentVaultState.activeAccount = {
        id: imported.id,
        type: KeyringAccountType.Imported,
      };

      await expect(
        keyringManager.getPubkey(imported.id, false)
      ).rejects.toThrow(/watch-only|Public key|not available/i);
      await expect(
        keyringManager.getBip32Path(imported.id, false)
      ).rejects.toThrow(/watch-only|BIP32|not available/i);
    });

    it('rejects duplicate watch-only import by address', async () => {
      const addr = 'sys1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq';
      const first = await (keyringManager as any).importWatchOnly(addr, 'WO1');
      currentVaultState.accounts[KeyringAccountType.Imported][first.id] = {
        id: first.id,
        label: first.label,
        address: first.address,
        xpub: first.xpub,
        xprv: first.xprv,
        isImported: true,
        isTrezorWallet: false,
        isLedgerWallet: false,
        balances: { syscoin: 0, ethereum: 0 },
        assets: { syscoin: [], ethereum: [] },
      };
      await expect(
        (keyringManager as any).importWatchOnly(addr, 'WO2')
      ).rejects.toThrow(/already exists/i);
    });
  });
});
