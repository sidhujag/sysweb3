import { INetworkType } from '@sidhujag/sysweb3-network';
import { address, networks } from 'bitcoinjs-lib';
import bs58check from 'bs58check';

import { KeyringManager } from '../../../src/keyring-manager';
import { KeyringAccountType } from '../../../src/types';
import { descriptorChecksum } from '../../../src/utils/watch-descriptor';
import { FAKE_PASSWORD, PEACE_SEED_PHRASE } from '../../helpers/constants';
import { createFreshTestKeyring, setupMocks } from '../../helpers/setup';

const XPUB =
  'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ';
const WPKH = `wpkh(${XPUB})`;
const ADDRESS = 'bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw';
const BACKEND_ADDRESS = 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu';

describe('watch descriptor import and address lifecycle', () => {
  let manager: KeyringManager;
  let vault: any;
  let fetchMock: jest.MockedFunction<typeof fetch>;

  beforeEach(async () => {
    setupMocks();
    await setupTestVault(FAKE_PASSWORD);
    vault = createMockVaultState({
      networkType: INetworkType.Syscoin,
      chainId: 5700,
    });
    manager = await createFreshTestKeyring(
      PEACE_SEED_PHRASE,
      FAKE_PASSWORD,
      () => vault
    );
    vault.activeNetwork = {
      kind: INetworkType.Syscoin,
      chainId: 0,
      slip44: 0,
      currency: 'BTC',
      label: 'Bitcoin',
      url: 'https://watch-only.invalid/',
    };
    fetchMock = jest.mocked(global.fetch);
    fetchMock.mockClear();
    expect(() =>
      address.toOutputScript(BACKEND_ADDRESS, networks.bitcoin)
    ).not.toThrow();
    fetchMock.mockImplementation(
      async () =>
        ({
          ok: true,
          json: async () => ({
            address: BACKEND_ADDRESS,
            tokens: [
              {
                type: 'XPUBAddress',
                name: BACKEND_ADDRESS,
                path: "m/84'/0'/0'/0/0",
              },
            ],
          }),
        } as Response)
    );
  });

  afterEach(async () => {
    await manager?.destroy();
  });

  const activate = (account: any) => {
    vault.accounts.Imported[account.id] = account;
    vault.activeAccount = { id: account.id, type: KeyringAccountType.Imported };
  };

  it.each([
    [`pkh(${XPUB})`, '1NsJS4DAHLcegD63trZurmkLm23TRAujXd'],
    [`sh(wpkh(${XPUB}))`, '39oRj36VbCJdky8wsPCT5FMQNRUUekuoUr'],
    [WPKH, ADDRESS],
    [
      `tr(${XPUB})`,
      'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr',
    ],
  ])(
    'imports script family case %# with locally bound address',
    async (identifier, address) => {
      const account = await manager.importWatchOnly(
        identifier,
        'Public descriptor'
      );
      expect(account).toMatchObject({
        address,
        xpub: identifier,
        xprv: '',
        isImported: true,
        label: 'Public descriptor',
        isLedgerWallet: false,
        isTrezorWallet: false,
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock).toHaveBeenCalledWith(
        `https://watch-only.invalid/api/v2/xpub/${encodeURIComponent(
          identifier
        )}?details=basic`
      );
      expect(vault.accounts.Imported).toEqual({});
    }
  );

  it('imports the supported Syscoin Testnet tpub descriptor from the Receive reproduction', async () => {
    const payload = Buffer.from(bs58check.decode(XPUB));
    payload.writeUInt32BE(0x043587cf, 0);
    const tpub = bs58check.encode(payload);
    const identifier = `wpkh(${tpub})`;
    vault.activeNetwork = {
      ...vault.activeNetwork,
      chainId: 5700,
      slip44: 1,
      currency: 'tSYS',
      label: 'Syscoin Testnet',
    };
    const account = await manager.importWatchOnly(identifier);
    expect(account).toMatchObject({
      address: 'tsys1qalwlmdxd2ggue4290ekzxl9tetg56neeepgwhk',
      xpub: identifier,
      xprv: '',
      isImported: true,
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://watch-only.invalid/api/v2/xpub/${encodeURIComponent(
        identifier
      )}?details=basic`
    );
  });

  it('preserves origin, ordered branches and checksum in the history reference', async () => {
    const body = `wpkh([d34db33f/84h/0h/0h]${XPUB}/<2;0>/*)`;
    const identifier = `${body}#${descriptorChecksum(body)}`;
    const account = await manager.importWatchOnly(identifier);
    expect(account.address).toBe('bc1qdjk5l8zfe5h5ex7vnhfj7rxu9fnd9d38c8plnx');
    expect(account.xpub).toBe(identifier);
    expect(fetchMock).toHaveBeenCalledWith(
      `https://watch-only.invalid/api/v2/xpub/${encodeURIComponent(
        identifier
      )}?details=basic`
    );
  });

  it('derives force-index-zero addresses without backend recipient authority', async () => {
    await expect(
      manager.getAddress(WPKH, false, { forceIndex0: true })
    ).resolves.toBe(ADDRESS);
    await expect(
      manager.getAddress(WPKH, true, { forceIndex0: true })
    ).resolves.toBe('bc1qm4y5h28kytu6uftd94vtcjppffk5sx0hgat2c5');
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([false, true])(
    'refuses descriptor rotation with change=%s',
    async (change) => {
      await expect(manager.getAddress(WPKH, change)).rejects.toThrow(
        /descriptor|rotation|index/i
      );
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it.each([false, true])(
    'refuses change and receiving rotation for oldRecord=%s',
    async (oldRecord) => {
      const account = await manager.importWatchOnly(WPKH);
      activate(oldRecord ? { ...account, address: WPKH } : account);
      fetchMock.mockClear();
      await expect(manager.getChangeAddress(account.id)).rejects.toThrow(
        /descriptor|rotation|index/i
      );
      await expect(manager.getNewChangeAddress()).rejects.toThrow(
        /descriptor|rotation|index/i
      );
      await expect(manager.updateReceivingAddress()).rejects.toThrow(
        /descriptor|rotation|index/i
      );
      expect(fetchMock).not.toHaveBeenCalled();
    }
  );

  it('retains watch-only derivation guards after address differs from descriptor', async () => {
    const account = await manager.importWatchOnly(WPKH);
    activate(account);
    fetchMock.mockClear();
    await expect(manager.getPubkey(account.id, false)).rejects.toThrow(
      /watch-only/i
    );
    await expect(manager.getBip32Path(account.id, false)).rejects.toThrow(
      /watch-only/i
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    `wsh(${XPUB})`,
    `${WPKH}#aaaaaaaa`,
    'wpkh(xprv-not-a-public-key)',
    `wpkh(${XPUB}/0h/*)`,
    `wpkh(${XPUB}/2147483648/*)`,
  ])(
    'rejects locally invalid descriptor case %# before HTTP',
    async (identifier) => {
      await expect(manager.importWatchOnly(identifier)).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
      expect(vault.accounts.Imported).toEqual({});
    }
  );

  it('rejects a canonical-address duplicate before querying Blockbook', async () => {
    const account = await manager.importWatchOnly(ADDRESS);
    activate(account);
    fetchMock.mockClear();
    await expect(manager.importWatchOnly(WPKH)).rejects.toThrow(
      /already exists/i
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects an exact-descriptor duplicate from an old invalid address record', async () => {
    const account = await manager.importWatchOnly(WPKH);
    activate({ ...account, address: WPKH });
    fetchMock.mockClear();
    await expect(manager.importWatchOnly(WPKH)).rejects.toThrow(
      /already exists/i
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not import when the backend rejects an otherwise valid descriptor', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      statusText: 'Descriptor is unavailable',
      text: async () => JSON.stringify({ error: 'Descriptor is unavailable' }),
    } as Response);
    await expect(manager.importWatchOnly(WPKH)).rejects.toThrow(
      'Descriptor is unavailable'
    );
    expect(vault.accounts.Imported).toEqual({});
  });
});
