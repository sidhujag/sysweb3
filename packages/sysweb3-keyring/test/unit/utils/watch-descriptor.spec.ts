import { INetwork, INetworkType } from '@sidhujag/sysweb3-network';
import bs58check from 'bs58check';

import {
  deriveDescriptorAddress,
  descriptorChecksum,
} from '../../../src/utils/watch-descriptor';

// Public BIP86 test vector; no seed/private key or remote service is used.
// https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki#test-vectors
const XPUB =
  'xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ';
const network: INetwork = {
  kind: INetworkType.Syscoin,
  chainId: 0,
  slip44: 0,
  currency: 'BTC',
  label: 'Bitcoin',
  url: 'https://offline.invalid',
};
const descriptor = (type = 'wpkh', path = '') => {
  return type === 'sh(wpkh)'
    ? `sh(wpkh(${XPUB}${path}))`
    : `${type}(${XPUB}${path})`;
};
const publicPayload = Buffer.from(bs58check.decode(XPUB));
const withVersion = (version: number) => {
  const payload = Buffer.from(publicPayload);
  payload.writeUInt32BE(version, 0);
  return bs58check.encode(payload);
};

beforeEach(() => {
  jest.mocked(global.fetch).mockClear();
});
afterEach(() => {
  expect(global.fetch).not.toHaveBeenCalled();
});

describe('public descriptor receiving address', () => {
  it.each([
    ['pkh', '1NsJS4DAHLcegD63trZurmkLm23TRAujXd'],
    ['sh(wpkh)', '39oRj36VbCJdky8wsPCT5FMQNRUUekuoUr'],
    ['wpkh', 'bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw'],
    ['tr', 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr'],
  ])(
    'preserves the declared %s script at default branch/index zero',
    (type, expected) => {
      expect(deriveDescriptorAddress(descriptor(type), network)).toBe(expected);
    }
  );

  it('uses the first declared branch and preserves multipath order', () => {
    const expected = 'bc1qdjk5l8zfe5h5ex7vnhfj7rxu9fnd9d38c8plnx';
    expect(deriveDescriptorAddress(descriptor('wpkh', '/2/*'), network)).toBe(
      expected
    );
    expect(
      deriveDescriptorAddress(descriptor('wpkh', '/<2;0>/*'), network)
    ).toBe(expected);
    expect(
      deriveDescriptorAddress(descriptor('wpkh', '/{2,0}/*'), network)
    ).toBe(expected);
    expect(
      deriveDescriptorAddress(descriptor('wpkh', '/<2;0>/*'), network, {
        change: true,
      })
    ).toBe('bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw');
  });

  it('uses the second declared branch only when change was requested', () => {
    expect(
      deriveDescriptorAddress(descriptor(), network, { change: true })
    ).toBe('bc1qm4y5h28kytu6uftd94vtcjppffk5sx0hgat2c5');
    expect(() =>
      deriveDescriptorAddress(descriptor('wpkh', '/0/*'), network, {
        change: true,
      })
    ).toThrow();
  });

  it('derives the exact requested nonzero index', () => {
    expect(
      deriveDescriptorAddress(descriptor('tr', '/0/*'), network, { index: 1 })
    ).toBe('bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh');
  });

  it.each(["d34db33f/84'/0'/0'", 'd34db33f/84h/0h/0h', 'D34DB33F/44h/1/7'])(
    'treats origin %s as metadata, not an additional derivation',
    (origin) => {
      expect(
        deriveDescriptorAddress(`wpkh([${origin}]${XPUB}/0/*)`, network)
      ).toBe('bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw');
    }
  );

  it('checks the supplied checksum without changing the descriptor', () => {
    const body = descriptor('wpkh', '/0/*');
    const input = `${body}#${descriptorChecksum(body)}`;
    expect(deriveDescriptorAddress(input, network)).toBe(
      'bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw'
    );
    expect(input).toBe(`${body}#${descriptorChecksum(body)}`);
  });

  it('matches the independent Bitcoin Core checksum vector', () => {
    expect(descriptorChecksum('raw(deadbeef)')).toBe('89f8spxm');
    expect(descriptorChecksum('\u2603')).toBe('');
  });

  it('uses registered coin encoding instead of the key version', () => {
    const testnet = { ...network, chainId: 5700, slip44: 1, currency: 'tSYS' };
    expect(deriveDescriptorAddress(descriptor(), testnet)).toBe(
      'tsys1qalwlmdxd2ggue4290ekzxl9tetg56neeepgwhk'
    );
    expect(
      deriveDescriptorAddress(`wpkh(${withVersion(0x043587cf)})`, testnet)
    ).toBe('tsys1qalwlmdxd2ggue4290ekzxl9tetg56neeepgwhk');
    expect(
      deriveDescriptorAddress(`wpkh(${withVersion(0x04b24746)})`, network)
    ).toBe('bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw');
  });

  it('accepts ten declared branches without expanding the entire set', () => {
    expect(
      deriveDescriptorAddress(
        descriptor('wpkh', '/<0;1;2;3;4;5;6;7;8;9>/*'),
        network
      )
    ).toBe('bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw');
  });

  it.each([
    descriptor('addr'),
    descriptor('pk'),
    descriptor('wsh'),
    `sh(${XPUB})`,
    `tr(${XPUB},{pk(${XPUB}),pk(${XPUB})})`,
    `wpkh(03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)`,
    `${descriptor()})`,
    `${descriptor()}trailing`,
    ` wpkh(${XPUB})`,
    `wpkh( ${XPUB})`,
    descriptor('wpkh', '/0/1'),
    descriptor('wpkh', '/0/1/*'),
    descriptor('wpkh', '/0h/*'),
    descriptor('wpkh', "/0'/*"),
    descriptor('wpkh', '/0/*h'),
    descriptor('wpkh', '/2147483648/*'),
    descriptor('wpkh', '/9007199254740993/*'),
    descriptor('wpkh', '/<-1;0>/*'),
    descriptor('wpkh', '/<0;2147483648>/*'),
    descriptor('wpkh', '/<0;1;2;3;4;5;6;7;8;9;10>/*'),
    `wpkh([not-a-fingerprint/84h/0h/0h]${XPUB})`,
    `wpkh([d34db33f/84H/0H/0H]${XPUB})`,
    `wpkh([d34db33f/2147483648h/0h/0h]${XPUB})`,
    `wpkh([d34db33f/84h/0h]${XPUB})`,
    `${descriptor()}#aaaaaaaa`,
    `${descriptor()}#${descriptorChecksum(descriptor())}#extra`,
    `wpkh(${XPUB.slice(0, -1)}1)`,
    `wpkh(${XPUB.repeat(150)})`,
  ])('rejects unsupported or malformed public syntax case %#', (input) => {
    expect(() => deriveDescriptorAddress(input, network)).toThrow();
  });

  it('rejects private-key payloads even when encoded with public version bytes', () => {
    const payload = Buffer.from(publicPayload);
    payload.fill(0, 45);
    payload[77] = 1; // Publicly known synthetic scalar, not a wallet secret.
    expect(() =>
      deriveDescriptorAddress(`wpkh(${bs58check.encode(payload)})`, network)
    ).toThrow();
    payload.writeUInt32BE(0x0488ade4, 0);
    expect(() =>
      deriveDescriptorAddress(`wpkh(${bs58check.encode(payload)})`, network)
    ).toThrow();
  });

  it.each([-1, 1.5, 0x80000000, NaN, Infinity, '1', null])(
    'rejects invalid index %s',
    (index) => {
      expect(() =>
        deriveDescriptorAddress(descriptor(), network, { index } as any)
      ).toThrow();
    }
  );

  it('rejects a nonboolean change request', () => {
    expect(() =>
      deriveDescriptorAddress(descriptor(), network, { change: 'yes' } as any)
    ).toThrow();
  });

  it.each([
    { ...network, kind: INetworkType.Ethereum, slip44: 60, currency: 'ETH' },
    { ...network, slip44: 987654, currency: 'Unknown' },
    { ...network, currency: 'Unknown' },
    { ...network, slip44: 1, currency: 'BTC' },
  ])('rejects EVM, unknown or mismatched coin identity', (input) => {
    expect(() => deriveDescriptorAddress(descriptor(), input)).toThrow();
  });

  it('does not enable Taproot only because the payment library supports it', () => {
    expect(() =>
      deriveDescriptorAddress(descriptor('tr'), {
        ...network,
        slip44: 57,
        currency: 'SYS',
      })
    ).toThrow();
    expect(() =>
      deriveDescriptorAddress(descriptor('tr'), {
        ...network,
        slip44: 1,
        currency: 'tSYS',
      })
    ).toThrow();
  });

  it('rejects witness scripts for a registered non-SegWit coin', () => {
    expect(() =>
      deriveDescriptorAddress(descriptor(), {
        ...network,
        slip44: 3,
        currency: 'DOGE',
      })
    ).toThrow();
  });
});
