import { INetworkType } from '@sidhujag/sysweb3-network';
import * as bjs from 'bitcoinjs-lib';
import wif from 'wif';

import { KeyringManager, KeyringAccountType } from '../../../src';
import { FAKE_PASSWORD, PEACE_SEED_PHRASE } from '../../helpers/constants';
import { setupMocks } from '../../helpers/setup';

// Helper to generate deterministic WIFs from a fixed private key for given network
const generateWif = (network: any) => {
  const priv = Buffer.from(
    '0101010101010101010101010101010101010101010101010101010101010101',
    'hex'
  );
  const version = network.wif; // 0x80 mainnet, 0xef testnet
  return wif.encode(version, priv, true);
};

describe('WIF Import - KeyringManager', () => {
  let keyringManager: KeyringManager;
  let mockVaultStateGetter: jest.Mock;
  let currentVaultState: any;

  beforeEach(async () => {
    setupMocks();
    await setupTestVault(FAKE_PASSWORD);
  });

  describe('Syscoin mainnet', () => {
    let MAINNET_WIF: string;

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

      MAINNET_WIF = generateWif(bjs.networks.bitcoin);
    });

    it('validates and imports a mainnet WIF as single-address account', async () => {
      const validation = (keyringManager as any).validateWif(MAINNET_WIF);
      expect(validation.isValid).toBe(true);

      const imported = await keyringManager.importAccount(
        MAINNET_WIF,
        'WIF Import'
      );
      expect(imported.isImported).toBe(true);
      expect(imported.label).toBe('WIF Import');
      // xpub should equal address to mark single-address mode
      expect(imported.xpub).toBe(imported.address);

      // Update mock vault with imported account
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
      // Switch active account to the imported one for getter calls
      currentVaultState.activeAccount = {
        id: imported.id,
        type: KeyringAccountType.Imported,
      };

      // Single-address getters behavior
      const changeAddr = await keyringManager.getChangeAddress(imported.id);
      expect(changeAddr).toBe(imported.address);
      await expect(
        keyringManager.getPubkey(imported.id, false)
      ).rejects.toThrow(/not available|Public key/);
      await expect(
        keyringManager.getBip32Path(imported.id, false)
      ).rejects.toThrow(/not available|BIP32/);
    });
  });

  describe('Syscoin testnet mismatch', () => {
    let TESTNET_WIF: string;

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

      TESTNET_WIF = generateWif(bjs.networks.testnet);
    });

    it('rejects mainnet WIF on testnet (validateWif false)', async () => {
      const mainnetWif = generateWif(bjs.networks.bitcoin);
      const validation = (keyringManager as any).validateWif(mainnetWif);
      expect(validation.isValid).toBe(false);
    });

    it('accepts testnet WIF on testnet', async () => {
      const validation = (keyringManager as any).validateWif(TESTNET_WIF);
      expect(validation.isValid).toBe(true);
    });
  });
});
