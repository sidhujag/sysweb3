import { retryableFetch } from '../src/retryUtils';

it.each([400, 401, 403, 404, 422])(
  'preserves permanent HTTP %s despite retry digits in its body',
  async (status) => {
    const fetch = jest
      .spyOn(global, 'fetch')
      .mockResolvedValue(new Response('requestId=503 or 429', { status }));
    try {
      await expect(retryableFetch('https://rpc.example')).rejects.toMatchObject(
        { status }
      );
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      fetch.mockRestore();
    }
  }
);

it.each([429, 503])(
  'retains retries for authoritative HTTP %s',
  async (status) => {
    jest.useFakeTimers();
    const fetch = jest
      .spyOn(global, 'fetch')
      .mockImplementation(async () => new Response('busy', { status }));
    try {
      const result = expect(
        retryableFetch('https://rpc.example')
      ).rejects.toMatchObject({ status });
      await jest.runAllTimersAsync();
      await result;
      expect(fetch).toHaveBeenCalledTimes(4);
    } finally {
      fetch.mockRestore();
      jest.useRealTimers();
    }
  }
);
