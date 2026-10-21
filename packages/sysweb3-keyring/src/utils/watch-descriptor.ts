import ecc from '@bitcoinerlab/secp256k1';
import {
  findCoin,
  getNetworkConfig,
  INetwork,
  INetworkType,
} from '@sidhujag/sysweb3-network';
import { BIP32Factory } from 'bip32';
import bs58check from 'bs58check';
import { utils as syscoinUtils } from 'syscoinjs-lib';

const bip32 = BIP32Factory(ecc);
const bitcoin = syscoinUtils.bitcoinjs;
const invalid = (): never => {
  throw new Error('Unsupported or invalid public watch-only descriptor');
};
const childIndex = (value: number): number => {
  if (!Number.isInteger(value) || value < 0 || value >= 0x80000000)
    return invalid();
  return value;
};

// Bitcoin Core's descriptor checksum, also used by Pali's public-input guard.
export const descriptorChecksum = (value: string): string => {
  const input =
    '0123456789()[],\'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';
  const output = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const generators = [
    'f5dee51989',
    'a9fdca3312',
    '1bab10e32d',
    '3706b1677a',
    '644d626ffd',
  ].map((hex) => BigInt(`0x${hex}`));
  const poly = (current: bigint, next: number) => {
    const top = current >> BigInt(35);
    let result =
      ((current & BigInt('0x7ffffffff')) << BigInt(5)) ^ BigInt(next);
    generators.forEach((generator, index) => {
      if ((top & (BigInt(1) << BigInt(index))) !== BigInt(0))
        result ^= generator;
    });
    return result;
  };
  let checksum = BigInt(1),
    group = 0,
    count = 0;
  for (const character of value) {
    const position = input.indexOf(character);
    if (position < 0) return '';
    checksum = poly(checksum, position & 31);
    group = group * 3 + (position >> 5);
    if (++count === 3) {
      checksum = poly(checksum, group);
      group = count = 0;
    }
  }
  if (count) checksum = poly(checksum, group);
  for (let index = 0; index < 8; index++) checksum = poly(checksum, 0);
  checksum ^= BigInt(1);
  return Array.from(
    { length: 8 },
    (_, index) =>
      output[Number((checksum >> BigInt(5 * (7 - index))) & BigInt(31))]
  ).join('');
};

/** Derive only the single-key public descriptor forms supported by Blockbook. */
export const deriveDescriptorAddress = (
  descriptor: string,
  network: INetwork,
  options?: { change?: boolean; index?: number }
): string => {
  if (
    typeof descriptor !== 'string' ||
    !descriptor ||
    descriptor.length > 16384 ||
    /\s/.test(descriptor) ||
    (options?.change !== undefined && typeof options.change !== 'boolean')
  )
    return invalid();
  const parts = descriptor.split('#');
  if (
    parts.length > 2 ||
    (parts.length === 2 && descriptorChecksum(parts[0]) !== parts[1])
  )
    return invalid();

  const simple = /^(pkh|wpkh|tr)\(([^()]*)\)$/.exec(parts[0]);
  const wrapped = /^sh\(wpkh\(([^()]*)\)\)$/.exec(parts[0]);
  if (!simple && !wrapped) return invalid();
  const type = simple?.[1] || 'sh(wpkh)';
  const key = simple?.[2] || wrapped?.[1] || '';
  const parsed =
    /^(?:\[([\da-fA-F]{8})\/(\d+)['h]\/(\d+)['h]?\/(\d+)['h]?\])?([1-9A-HJ-NP-Za-km-z]{100,112})(?:\/(\d+|\{\d+(?:,\d+)*\}|<\d+(?:;\d+)*>)\/\*)?$/.exec(
      key
    );
  if (!parsed) return invalid();
  if (parsed[1])
    parsed.slice(2, 5).forEach((value) => childIndex(Number(value)));
  const branches = parsed[6]
    ? parsed[6]
        .replace(/[{}<>]/g, '')
        .split(/[,;]/)
        .map((value) => childIndex(Number(value)))
    : [0, 1];
  if (branches.length > 10) return invalid();
  const branch = branches[options?.change ? 1 : 0];
  if (branch === undefined) return invalid();
  const index = childIndex(options?.index === undefined ? 0 : options.index);

  if (!network || network.kind !== INetworkType.Syscoin) return invalid();
  const coin = findCoin({
    slip44: network.slip44,
    name: network.currency,
    exactMatch: true,
  });
  if (
    !coin ||
    (type !== 'pkh' && coin.segwit !== true) ||
    (type === 'tr' && coin.taproot !== true)
  )
    return invalid();
  const config = getNetworkConfig(network.slip44, network.currency);
  const addressNetwork =
    network.slip44 === 1 ? config.networks.testnet : config.networks.mainnet;

  const payload = Buffer.from(bs58check.decode(parsed[5]));
  if (payload.length !== 78 || ![2, 3].includes(payload[45])) return invalid();
  const root = bip32.fromBase58(parsed[5], {
    ...addressNetwork,
    bip32: { public: payload.readUInt32BE(0), private: 0x0488ade4 },
  });
  if (!root.isNeutered()) return invalid();
  const branchNode = root.derive(branch);
  const addressNode = branchNode.derive(index);
  // Do not let BIP32's invalid-child retry silently select a different path.
  if (branchNode.index !== branch || addressNode.index !== index)
    return invalid();
  const pubkey = addressNode.publicKey;
  const payment =
    type === 'pkh'
      ? bitcoin.payments.p2pkh({ pubkey, network: addressNetwork })
      : type === 'wpkh'
      ? bitcoin.payments.p2wpkh({ pubkey, network: addressNetwork })
      : type === 'tr'
      ? bitcoin.payments.p2tr({
          internalPubkey: pubkey.slice(1),
          network: addressNetwork,
        })
      : bitcoin.payments.p2sh({
          redeem: bitcoin.payments.p2wpkh({ pubkey, network: addressNetwork }),
          network: addressNetwork,
        });
  if (
    !payment.address ||
    !payment.output ||
    !Buffer.from(
      bitcoin.address.toOutputScript(payment.address, addressNetwork)
    ).equals(Buffer.from(payment.output))
  )
    return invalid();
  return payment.address;
};
