import path from 'path';

// The shared setup preloads the SDK with a transport stub. Resolve the installed
// package entry explicitly so this gate exercises Ledger's real model lookup and
// WebHID implementation, with only browser/device I/O replaced.
jest.resetModules();
const transportPackagePath = require.resolve(
  '@ledgerhq/hw-transport-webhid/package.json'
);
const transportPackage = jest.requireActual(transportPackagePath);
const transportModule = jest.requireActual(
  path.join(path.dirname(transportPackagePath), transportPackage.main)
);
const WebHID = transportModule.default;
const devices = jest.requireActual('@ledgerhq/devices');

let managerModule: typeof import('../../../src/hardware-wallet-manager');
jest.isolateModules(() => {
  jest.doMock('@ledgerhq/hw-transport-webhid', () => transportModule);
  managerModule = require('../../../src/hardware-wallet-manager');
});

// USB identifiers published by Ledger; public fixtures, not physical devices.
// Gen5/Flex retain their internal Apex/Europa identifiers in LedgerJS.
const currentModels = [
  {
    name: 'Nano Gen5',
    model: 'apex',
    productId: 0x8011,
    legacyProductId: 0x0008,
  },
  { name: 'Stax', model: 'stax', productId: 0x6011, legacyProductId: 0x0006 },
  { name: 'Flex', model: 'europa', productId: 0x7011, legacyProductId: 0x0007 },
];

const fakeDevice = (productId: number, vendorId = 0x2c97) => ({
  productId,
  vendorId,
  // Recognition must come from the USB ID, not an assumed product-name alias.
  productName: 'Untrusted HID product name',
  open: jest.fn().mockResolvedValue(undefined),
  close: jest.fn().mockResolvedValue(undefined),
  addEventListener: jest.fn(),
  removeEventListener: jest.fn(),
});

describe('installed Ledger support for current USB devices', () => {
  let navigatorDescriptor: PropertyDescriptor | undefined;
  let manager: InstanceType<typeof managerModule.HardwareWalletManager>;
  let hid: {
    getDevices: jest.Mock;
    requestDevice: jest.Mock;
    addEventListener: jest.Mock;
    removeEventListener: jest.Mock;
  };

  beforeEach(() => {
    jest.useFakeTimers();
    navigatorDescriptor = Object.getOwnPropertyDescriptor(global, 'navigator');
    hid = {
      getDevices: jest.fn().mockResolvedValue([]),
      requestDevice: jest.fn().mockResolvedValue([]),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
    };
    Object.defineProperty(global, 'navigator', {
      configurable: true,
      value: { hid },
    });
  });

  afterEach(async () => {
    if (manager) await manager.destroy();
    manager = undefined as any;
    // SDK connection deadlines remain pending after a successful race.
    jest.clearAllTimers();
    jest.useRealTimers();
    if (navigatorDescriptor) {
      Object.defineProperty(global, 'navigator', navigatorDescriptor);
    } else {
      delete (global as any).navigator;
    }
  });

  it.each(currentModels)(
    'identifies both USB encodings for $name using the real Ledger dependency',
    ({ model, productId, legacyProductId }) => {
      expect(jest.isMockFunction(devices.identifyUSBProductId)).toBe(false);
      expect(devices.identifyUSBProductId(productId)?.id).toBe(model);
      expect(devices.identifyUSBProductId(legacyProductId)?.id).toBe(model);
    }
  );

  it.each(currentModels)(
    'opens $name through the SDK manager and real WebHID chooser',
    async ({ model, productId }) => {
      const device = fakeDevice(productId);
      const unrelatedDevice = fakeDevice(productId, 0x1234);
      hid.getDevices.mockResolvedValue([unrelatedDevice]);
      hid.requestDevice.mockResolvedValue([device]);
      manager = new managerModule.HardwareWalletManager();

      const transport = await manager.getLedgerConnection();

      expect(transport).toBeInstanceOf(WebHID);
      expect(transport.deviceModel?.id).toBe(model);
      expect((transport as any).device).toBe(device);
      expect(device.open).toHaveBeenCalledTimes(1);
      expect(unrelatedDevice.open).not.toHaveBeenCalled();
      expect(hid.requestDevice).toHaveBeenCalledWith({
        filters: [{ vendorId: 0x2c97 }],
      });
      expect(manager.getStatus()).toContainEqual(
        expect.objectContaining({ type: 'ledger', connected: true })
      );
      expect(await manager.getLedgerConnection()).toBe(transport);
      expect(hid.getDevices).toHaveBeenCalledTimes(1);
      expect(hid.requestDevice).toHaveBeenCalledTimes(1);

      await manager.destroy();
      expect(device.close).toHaveBeenCalledTimes(1);
    }
  );

  it('reuses an authorized current device without another permission request', async () => {
    const device = fakeDevice(0x8011);
    const unrelatedDevice = fakeDevice(0x8011, 0x1234);
    hid.getDevices.mockResolvedValue([unrelatedDevice, device]);
    manager = new managerModule.HardwareWalletManager();

    const transport = await manager.getLedgerConnection();

    expect(transport).toBeInstanceOf(WebHID);
    expect(transport.deviceModel?.id).toBe('apex');
    expect(hid.requestDevice).not.toHaveBeenCalled();
    expect(device.open).toHaveBeenCalledTimes(1);
    expect(unrelatedDevice.open).not.toHaveBeenCalled();
  });

  it.each([0x9011, 0xffff])(
    'does not label unknown USB product ID %i as a supported model',
    (productId) => {
      const transport = new WebHID(fakeDevice(productId));

      expect(devices.identifyUSBProductId(productId)).toBeUndefined();
      expect(transport.deviceModel).toBeUndefined();
    }
  );
});
