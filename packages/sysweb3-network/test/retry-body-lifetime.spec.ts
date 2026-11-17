import { retryableFetch } from '../src/retryUtils';
import { clearRpcCaches, validateEthRpc } from '../src/rpc';

const endpoint = 'https://discovery-body-lifetime.invalid';

beforeEach(() => {
  jest.useFakeTimers();
  clearRpcCaches();
});
afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

const busyResponse = (status: number, cancel: jest.Mock) =>
  new Response(new ReadableStream({ cancel }), { status });

it.each([429, 503])(
  'releases discarded HTTP %s bodies without waiting on cancellation',
  async (status) => {
    const cancelled = jest.fn(() => new Promise<void>(() => undefined));
    const signals: AbortSignal[] = [];
    const fetch = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async (_, init) => {
        signals.push(init?.signal as AbortSignal);
        return signals.length === 1
          ? busyResponse(status, cancelled)
          : new Response('healthy');
      });
    const pending = retryableFetch(endpoint);
    await jest.advanceTimersByTimeAsync(1000);
    const response = await pending;
    expect(await response.text()).toBe('healthy');
    expect(cancelled).toHaveBeenCalledTimes(1);
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(signals[0].aborted).toBe(true);
    // A successful caller still owns its response body after the headers arrive.
    expect(signals[1].aborted).toBe(false);
  }
);

it('does not abort the parent signal between retries', async () => {
  const parent = new AbortController();
  const cancelled = jest.fn();
  const fetch = jest
    .spyOn(global, 'fetch')
    .mockResolvedValueOnce(busyResponse(503, cancelled))
    .mockResolvedValueOnce(new Response('healthy'));
  const pending = retryableFetch(endpoint, { signal: parent.signal });
  await jest.advanceTimersByTimeAsync(1000);
  expect(await (await pending).text()).toBe('healthy');
  expect(cancelled).toHaveBeenCalledTimes(1);
  expect(parent.signal.aborted).toBe(false);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('releases every exhausted response within the unchanged retry ceiling', async () => {
  const cancelled = jest.fn();
  const signals: AbortSignal[] = [];
  const fetch = jest
    .spyOn(global, 'fetch')
    .mockImplementation(async (_, init) => {
      signals.push(init?.signal as AbortSignal);
      return busyResponse(503, cancelled);
    });
  const rejected = expect(
    validateEthRpc(endpoint, false)
  ).rejects.toMatchObject({ status: 503 });
  await jest.advanceTimersByTimeAsync(7000);
  await rejected;
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(cancelled).toHaveBeenCalledTimes(4);
  expect(new Set(signals).size).toBe(1);
  expect(signals.every((signal) => signal.aborted)).toBe(true);
  expect(jest.getTimerCount()).toBe(0);
});

it('closes discovery ownership after consuming success and preserves the validated cache', async () => {
  const cancelled = jest.fn();
  const signals: AbortSignal[] = [];
  const fetch = jest
    .spyOn(global, 'fetch')
    .mockImplementation(async (_, init) => {
      signals.push(init?.signal as AbortSignal);
      return signals.length === 1
        ? busyResponse(503, cancelled)
        : Response.json({ jsonrpc: '2.0', id: 1, result: '0x1' });
    });
  const pending = validateEthRpc(endpoint, false);
  await jest.advanceTimersByTimeAsync(1000);
  expect(await pending).toMatchObject({ chainId: 1 });
  expect(signals.every((signal) => signal.aborted)).toBe(true);
  expect(cancelled).toHaveBeenCalledTimes(1);
  expect(await validateEthRpc(endpoint, false)).toMatchObject({ chainId: 1 });
  expect(fetch).toHaveBeenCalledTimes(2);
  expect(jest.getTimerCount()).toBe(0);
});

it('consumes a permanent error once and closes discovery ownership', async () => {
  let signal: AbortSignal | undefined;
  const response = new Response('request 503 is unavailable', { status: 501 });
  const fetch = jest
    .spyOn(global, 'fetch')
    .mockImplementation(async (_, init) => {
      signal = init?.signal as AbortSignal;
      return response;
    });
  await expect(validateEthRpc(endpoint, false)).rejects.toMatchObject({
    status: 501,
  });
  expect(response.bodyUsed).toBe(true);
  expect(signal?.aborted).toBe(true);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(jest.getTimerCount()).toBe(0);
});
