import { HardwareWalletManager } from './hardware-wallet-manager';

/**
 * Singleton wrapper for HardwareWalletManager to ensure a single instance
 * is shared across all KeyringManager instances. This prevents "device already open"
 * errors when multiple networks try to connect to the same Ledger device.
 */
class HardwareWalletManagerSingleton {
  private static instance: HardwareWalletManager | null = null;

  /**
   * Get the shared HardwareWalletManager instance
   * Creates one if it doesn't exist
   */
  static getInstance(): HardwareWalletManager {
    if (!HardwareWalletManagerSingleton.instance) {
      HardwareWalletManagerSingleton.instance = new HardwareWalletManager();
    }
    return HardwareWalletManagerSingleton.instance;
  }

  /**
   * Reset the singleton instance (useful for testing)
   */
  static resetInstance(): void {
    if (HardwareWalletManagerSingleton.instance) {
      // Clean up any existing connections
      HardwareWalletManagerSingleton.instance.destroy();
      HardwareWalletManagerSingleton.instance = null;
    }
  }
}

export { HardwareWalletManagerSingleton };