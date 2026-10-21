import { INetworkType } from '../src/networks';
import { clearRpcCaches, getEthRpc } from '../src/rpc';

describe('getEthRpc explorer pathname normalization', () => {
  const unknownChainId = 1234567890123;
  const originalFetch = global.fetch;
  let fetchMock: jest.Mock;

  beforeEach(() => {
    clearRpcCaches();
    fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        jsonrpc: '2.0',
        id: 1,
        result: `0x${unknownChainId.toString(16)}`,
      }),
    });
    global.fetch = fetchMock;
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it.each([
    ['origin', 'https://explorer.invalid', 'https://explorer.invalid/'],
    ['root', 'https://explorer.invalid/', 'https://explorer.invalid/'],
    [
      'path',
      'https://explorer.invalid/public',
      'https://explorer.invalid/public/',
    ],
    [
      'path slash',
      'https://explorer.invalid/public/',
      'https://explorer.invalid/public/',
    ],
    [
      'query',
      'https://explorer.invalid?view=compact',
      'https://explorer.invalid/?view=compact',
    ],
    [
      'path query',
      'https://explorer.invalid/public?view=compact',
      'https://explorer.invalid/public/?view=compact',
    ],
    [
      'path slash query',
      'https://explorer.invalid/public/?view=compact',
      'https://explorer.invalid/public/?view=compact',
    ],
    [
      'query ending in slash',
      'https://explorer.invalid/public?next=/',
      'https://explorer.invalid/public/?next=/',
    ],
    [
      'anchor',
      'https://explorer.invalid/public#section',
      'https://explorer.invalid/public/#section',
    ],
    [
      'root anchor',
      'https://explorer.invalid/#section',
      'https://explorer.invalid/#section',
    ],
    [
      'fragment ending in slash',
      'https://explorer.invalid/public#section/',
      'https://explorer.invalid/public/#section/',
    ],
    [
      'hash router',
      'https://explorer.invalid/public#/route?view=compact',
      'https://explorer.invalid/public/#/route?view=compact',
    ],
    [
      'root hash router',
      'https://explorer.invalid/#/route?view=compact',
      'https://explorer.invalid/#/route?view=compact',
    ],
    [
      'hashbang router',
      'https://explorer.invalid/public#!/route?view=compact',
      'https://explorer.invalid/public/#!/route?view=compact',
    ],
    [
      'query and hashbang',
      'https://explorer.invalid/public?view=compact#!/route?item=1',
      'https://explorer.invalid/public/?view=compact#!/route?item=1',
    ],
    [
      'encoded suffix bytes',
      'https://Explorer.invalid/%2f?key=a%2Bb&path=%2F%3f%23#/%2F?x=%2b',
      'https://Explorer.invalid/%2f/?key=a%2Bb&path=%2F%3f%23#/%2F?x=%2b',
    ],
    [
      'empty query',
      'https://explorer.invalid/public?',
      'https://explorer.invalid/public/?',
    ],
    [
      'empty fragment',
      'https://explorer.invalid/public#',
      'https://explorer.invalid/public/#',
    ],
    [
      'question mark inside fragment',
      'https://explorer.invalid/public#route?view=compact',
      'https://explorer.invalid/public/#route?view=compact',
    ],
    ['accepted non-URL value', 'not-a-url', 'not-a-url/'],
    ['accepted non-URL slash', 'not-a-url/', 'not-a-url/'],
    ['empty explorer', '', '/'],
  ])(
    'preserves %s while adding only a pathname slash',
    async (_label, explorer, expected) => {
      const input = {
        url: 'https://rpc.synthetic.invalid',
        explorer,
        apiUrl: 'https://api.synthetic.invalid/data?key=a%2Bb#anchor',
        label: 'Synthetic network',
        symbol: 'TEST',
      };
      const result = await getEthRpc(input, false);

      expect(result).toStrictEqual({
        formattedNetwork: {
          url: input.url,
          default: false,
          label: input.label,
          apiUrl: input.apiUrl,
          explorer: expected,
          currency: 'test',
          chainId: unknownChainId,
          slip44: 60,
          kind: INetworkType.Ethereum,
        },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toBe(input.url);
      expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toStrictEqual({
        jsonrpc: '2.0',
        method: 'eth_chainId',
        params: [],
        id: 1,
      });
      expect(input.explorer).toBe(explorer);
    }
  );

  it('retains an absent custom explorer as the existing slash value', async () => {
    const { formattedNetwork } = await getEthRpc(
      { url: 'https://rpc.synthetic.invalid', symbol: 'TEST' },
      false
    );
    expect(formattedNetwork.explorer).toBe('/');
  });

  it.each([17, true])(
    'retains string coercion for an accepted non-string explorer %s',
    async (explorer) => {
      const { formattedNetwork } = await getEthRpc(
        { url: 'https://rpc.synthetic.invalid', symbol: 'TEST', explorer },
        false
      );
      expect(formattedNetwork.explorer).toBe(`${explorer}/`);
    }
  );

  it('uses the registered explorer and native symbol when no override is supplied', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: '2.0', id: 1, result: '0x1' }),
    });
    const { formattedNetwork } = await getEthRpc(
      { url: 'https://rpc.synthetic.invalid' },
      false
    );
    expect(formattedNetwork.explorer).toBe('https://etherscan.io/');
    expect(formattedNetwork.currency).toBe('eth');
    expect(formattedNetwork.chainId).toBe(1);
  });

  it('still requires a symbol for an unregistered chain', async () => {
    await expect(
      getEthRpc(
        { url: 'https://rpc.synthetic.invalid', explorer: 'not-a-url' },
        false
      )
    ).rejects.toThrow('Must define a symbol');
  });

  it('still refuses a cooldown before issuing an RPC request', async () => {
    await expect(
      getEthRpc(
        {
          url: 'https://rpc.synthetic.invalid',
          symbol: 'TEST',
          explorer: 'https://explorer.invalid?view=compact',
        },
        true
      )
    ).rejects.toThrow('Cant make request, rpc cooldown is active');
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
