import { getNetworkConfig } from '@sidhujag/sysweb3-network';
import * as syscoinjs from 'syscoinjs-lib';

/**
 * Utility functions for PSBT conversion between Pali and syscoinjs formats
 */
export class PsbtUtils {
  /**
   * Import PSBT from Pali's exported format to syscoinjs PSBT object
   * @param psbtFromPali - PSBT data exported from Pali
   * @param network - Optional bitcoinjs network to anchor address/HRP
   * @returns syscoinjs PSBT object
   */
  static fromPali(psbtFromPali: any, network: any): any {
    // Anchor import to the correct bitcoinjs network to preserve address HRP
    const networkCfg = getNetworkConfig(network.slip44, network.currency);
    const isTestnet = network.slip44 === 1;
    const bitcoinjsNetwork = isTestnet
      ? networkCfg.networks.testnet
      : networkCfg.networks.mainnet;
    return syscoinjs.utils.importPsbtFromJson(psbtFromPali, bitcoinjsNetwork)
      .psbt;
  }

  /**
   * Export syscoinjs PSBT object to Pali's expected format
   * @param psbt - syscoinjs PSBT object
   * @returns PSBT data in Pali's expected format
   */
  static toPali(psbt: any): any {
    return syscoinjs.utils.exportPsbtToJson(psbt, undefined);
  }
}
