import * as ecc from '@bitcoinerlab/secp256k1';
import { getNetworkConfig } from '@sidhujag/sysweb3-network';
import { BIP32Factory } from 'bip32';
import { payments } from 'bitcoinjs-lib';

import { convertExtendedKeyVersion } from '../../src/utils/derivation-paths';

const bip32 = BIP32Factory(ecc);

/** Public account vectors from a deterministic test-only hardware seed. */
export function hardwareUtxoFixture(coin: string, slip44: number, index = 0) {
  const { networks, types } = getNetworkConfig(slip44, coin);
  const testnet = slip44 === 1;
  const network = testnet ? networks.testnet : networks.mainnet;
  const account = bip32
    .fromSeed(Buffer.alloc(32, 7), network)
    .derivePath(`m/84'/${slip44}'/${index}'`)
    .neutered();
  const xpub = account.toBase58();
  const version = testnet
    ? types.zPubType.testnet.vpub
    : types.zPubType.mainnet.zpub;
  return {
    xpub,
    descriptor: convertExtendedKeyVersion(xpub, version),
    address: payments.p2wpkh({
      network,
      pubkey: account.derive(0).derive(0).publicKey,
    }).address!,
  };
}
