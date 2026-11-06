import {
  bufferedEvmGasLimit,
  getEvmFeeData,
  parseEvmFeeQuantity,
  planEvmCancellationFees,
  planEvmSpeedUpFees,
  EvmFeeReader,
} from '../../src/evm-fees';

const fixture = () => ({
  getGasPrice: jest.fn().mockResolvedValue('0x7'),
  getBlock: jest.fn().mockResolvedValue({ baseFeePerGas: '0x5' }),
  send: jest.fn().mockResolvedValue('0x0'),
});

describe('shared Speed Up fee-only policy', () => {
  const originalGas = 21000n;
  const uint64 = (1n << 64n) - 1n;
  const uint256 = (1n << 256n) - 1n;
  const bounds = { chainId: 743211n, sampledBlockGasLimit: uint64 };

  it.each([
    [0n, 0n],
    [1n, 2n],
    [4n, 5n],
    [5n, 6n],
    [101n, 121n],
    [9007199254740993n, 10808639105689191n],
  ])(
    'keeps the exact legacy rate and maximum fee for %s wei',
    (gasPrice, bumped) => {
      const plan = planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: originalGas,
        gasPrice,
      });
      expect(plan).toEqual({
        type: 0,
        gasLimit: 25200n,
        gasPrice: bumped,
        maximumFee: 25200n * bumped,
      });
      expect(Object.isFrozen(plan)).toBe(true);
    }
  );

  it('strictly increases both dynamic fee fields with a positive cap', () => {
    expect(
      planEvmSpeedUpFees({
        ...bounds,
        type: 2,
        gasLimit: originalGas,
        maxFeePerGas: 5n,
        maxPriorityFeePerGas: 0n,
      })
    ).toEqual({
      type: 2,
      gasLimit: 25200n,
      maxFeePerGas: 6n,
      maxPriorityFeePerGas: 1n,
      maximumFee: 151200n,
    });
    expect(() =>
      planEvmSpeedUpFees({
        ...bounds,
        type: 2,
        gasLimit: originalGas,
        maxFeePerGas: 1n,
        maxPriorityFeePerGas: 2n,
      })
    ).toThrow('Invalid replacement fee');
  });

  it('rejects the first buffered gas limit outside uint64', () => {
    const largest = ((uint64 + 1n) * 100n - 1n) / 120n;
    expect(
      planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: largest,
        gasPrice: 0n,
      }).gasLimit
    ).toBe(uint64);
    expect(() =>
      planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: largest + 1n,
        gasPrice: 0n,
      })
    ).toThrow('Invalid replacement gas limit');
    expect(() =>
      planEvmSpeedUpFees({ ...bounds, type: 0, gasLimit: 0n, gasPrice: 0n })
    ).toThrow('Invalid replacement gas limit');
  });

  it('requires sampled bounds and enforces both block and protocol ceilings', () => {
    const input = { type: 0 as const, gasLimit: 25000000n, gasPrice: 1n };
    // @ts-expect-error A current sampled block limit is required.
    expect(() => planEvmSpeedUpFees({ ...input, chainId: 743211n })).toThrow();
    expect(
      planEvmSpeedUpFees({
        ...input,
        chainId: 743211n,
        sampledBlockGasLimit: 30000000n,
      }).gasLimit
    ).toBe(30000000n);
    expect(() =>
      planEvmSpeedUpFees({
        ...input,
        chainId: 743211n,
        sampledBlockGasLimit: 29999999n,
      })
    ).toThrow('network limit');
    expect(() =>
      planEvmSpeedUpFees({
        ...input,
        chainId: 1n,
        gasLimit: 14000000n,
        sampledBlockGasLimit: 30000000n,
      })
    ).toThrow('network limit');
    for (const block of [0n, -1n, undefined, 30000000]) {
      expect(() =>
        planEvmSpeedUpFees({
          ...input,
          chainId: 743211n,
          sampledBlockGasLimit: block as bigint,
        })
      ).toThrow();
    }
  });

  it('checks the uint256 maximum fee even when both factors fit individually', () => {
    const rateCap = uint256 / 25200n;
    const largest = ((rateCap + 1n) * 100n - 1n) / 120n;
    expect(
      planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: originalGas,
        gasPrice: largest,
      }).maximumFee
    ).toBeLessThanOrEqual(uint256);
    expect(() =>
      planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: originalGas,
        gasPrice: largest + 1n,
      })
    ).toThrow('Invalid replacement maximum fee');
    expect(() =>
      planEvmSpeedUpFees({
        ...bounds,
        type: 0,
        gasLimit: originalGas,
        gasPrice: uint256,
      })
    ).toThrow('Invalid replacement fee');
  });

  it('rejects non-bigint and negative rates without coercing values', () => {
    const toString = jest.fn(() => '1');
    for (const rate of [1, -1n, { toString }])
      expect(() =>
        planEvmSpeedUpFees({
          ...bounds,
          type: 0,
          gasLimit: originalGas,
          gasPrice: rate as bigint,
        })
      ).toThrow('Invalid replacement fee');
    expect(toString).not.toHaveBeenCalled();
  });
});

describe('restricted shared EVM fee discovery', () => {
  it('preserves type-2 zero tips, exact math and a frozen bigint DTO', async () => {
    const reader = fixture();
    const fee = await getEvmFeeData(reader);
    expect(fee).toEqual({
      gasPrice: 7n,
      baseFeePerGas: 5n,
      maxFeePerGas: 12n,
      maxPriorityFeePerGas: 0n,
    });
    expect(Object.isFrozen(fee)).toBe(true);
    expect(reader.send.mock.calls).toEqual([['eth_maxPriorityFeePerGas', []]]);
  });

  it('returns legacy only for an actual block without a base fee', async () => {
    const reader = fixture();
    reader.getBlock.mockResolvedValue({});
    expect(await getEvmFeeData(reader)).toEqual({
      gasPrice: 7n,
      maxFeePerGas: 0n,
      maxPriorityFeePerGas: 0n,
    });
    expect(reader.send).not.toHaveBeenCalled();
  });

  it('uses the actual median history reward only for unsupported priority RPC', async () => {
    const reader = fixture();
    reader.send.mockRejectedValueOnce(
      Object.assign(new Error('unsupported'), { code: -32601 })
    );
    reader.send.mockResolvedValueOnce({
      reward: [
        ['0x0', '0xa', '0x14'],
        ['0x0', '0x2', '0x4'],
        ['0x0', '0x4', '0x8'],
      ],
    });
    expect(await getEvmFeeData(reader)).toEqual({
      gasPrice: 7n,
      baseFeePerGas: 5n,
      maxFeePerGas: 18n,
      maxPriorityFeePerGas: 6n,
    });
    expect(reader.send.mock.calls[1]).toEqual([
      'eth_feeHistory',
      ['0x5', 'latest', [25, 50, 75]],
    ]);
  });

  it.each([
    { code: -32000 },
    { code: 'SYSWEB3_RPC_RESPONSE_INVALID' },
    { code: 'UNSUPPORTED_OPERATION' },
    {
      code: 'UNKNOWN_ERROR',
      error: { code: -32601 },
      payload: { method: 'eth_getBalance', params: [] },
    },
    { name: 'AbortError', code: -32601 },
  ])(
    'never converts another failure to history or legacy: %p',
    async (fields) => {
      const reader = fixture();
      const error = Object.assign(new Error('failed'), fields);
      reader.send.mockRejectedValue(error);
      await expect(getEvmFeeData(reader)).rejects.toBe(error);
      expect(reader.send).toHaveBeenCalledTimes(1);
    }
  );

  it('takes an immutable snapshot of the supplied override values', async () => {
    const reader = fixture();
    const options = { minPriorityFee: '3', feeMultiplier: 300 };
    reader.getGasPrice.mockImplementation(async () => {
      options.minPriorityFee = '99';
      options.feeMultiplier = 999;
      return '0x7';
    });
    expect(await getEvmFeeData(reader, options)).toEqual({
      gasPrice: 7n,
      baseFeePerGas: 5n,
      maxFeePerGas: 18n,
      maxPriorityFeePerGas: 3n,
    });
  });

  it('rejects changed ownership after a read before issuing the next read', async () => {
    const reader = fixture();
    let current = true;
    reader.getGasPrice.mockImplementation(async () => {
      current = false;
      return '0x7';
    });
    await expect(
      getEvmFeeData(reader, {
        assertCurrent: () => {
          if (!current) throw new Error('changed owner');
        },
      })
    ).rejects.toThrow('changed owner');
    expect(reader.getBlock).not.toHaveBeenCalled();
    expect(reader.send).not.toHaveBeenCalled();
  });

  it('rejects an asynchronous guard before any provider read', async () => {
    const reader = fixture();
    await expect(
      getEvmFeeData(reader, { assertCurrent: async () => undefined })
    ).rejects.toThrow('must be synchronous');
    expect(reader.getGasPrice).not.toHaveBeenCalled();
  });

  it.each(['option', 'reader'])(
    'promptly rejects pending %s cancellation without issuing another read',
    async (where) => {
      const reader = fixture();
      const controller = new AbortController();
      let finish!: (value: unknown) => void;
      reader.getGasPrice.mockReturnValue(
        new Promise((resolve) => {
          finish = resolve;
        })
      );
      const pending = getEvmFeeData(
        where === 'reader' ? { ...reader, signal: controller.signal } : reader,
        where === 'option' ? { signal: controller.signal } : {}
      );
      controller.abort();
      await expect(pending).rejects.toMatchObject({ name: 'AbortError' });
      finish('0x7');
      await Promise.resolve();
      expect(reader.getBlock).not.toHaveBeenCalled();
      expect(reader.send).not.toHaveBeenCalled();
    }
  );

  it.each([
    null,
    undefined,
    '0x',
    '-1',
    '1'.repeat(81),
    2n ** 256n,
    NaN,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    { _hex: '' },
  ])('rejects invalid or excessive quantities: %p', (value) => {
    expect(() => parseEvmFeeQuantity(value)).toThrow('Invalid');
  });

  it.each([
    { reward: Array.from({ length: 6 }, () => ['0x0', '0x1', '0x2']) },
    { reward: [['bad', '0x1', '0x2']] },
    { reward: [['0x0', '0x1', 'bad']] },
  ])(
    'bounds and validates the complete returned history: %p',
    async (history) => {
      const reader = fixture();
      reader.send.mockRejectedValueOnce(
        Object.assign(new Error('unsupported'), { code: -32601 })
      );
      reader.send.mockResolvedValueOnce(history);
      await expect(getEvmFeeData(reader)).rejects.toThrow();
    }
  );

  it('rejects overflow instead of returning a fee above uint256', async () => {
    const reader = fixture();
    reader.getBlock.mockResolvedValue({ baseFeePerGas: 2n ** 256n - 1n });
    await expect(getEvmFeeData(reader)).rejects.toThrow('Invalid maximum fee');
  });

  it('admits the existing SDK BigNumberish forms without imports', () => {
    for (const value of [
      1n,
      1,
      '1',
      '0x1',
      { _hex: '0x1' },
      { hex: '0x1' },
      { toString: () => '1' },
    ])
      expect(parseEvmFeeQuantity(value)).toBe(1n);
  });

  it('rechecks ownership before returning a legacy result', async () => {
    const reader = fixture();
    let current = true;
    reader.getBlock.mockResolvedValue(
      Object.defineProperty({}, 'baseFeePerGas', {
        get() {
          current = false;
          return null;
        },
      })
    );
    await expect(
      getEvmFeeData(reader, {
        assertCurrent: () => {
          if (!current) throw new Error('changed owner');
        },
      })
    ).rejects.toThrow('changed owner');
  });

  it('does not dispatch when the ownership guard aborts the signal', async () => {
    const reader = fixture();
    const controller = new AbortController();
    await expect(
      getEvmFeeData(reader, {
        signal: controller.signal,
        assertCurrent: () => {
          controller.abort();
        },
      })
    ).rejects.toMatchObject({ name: 'AbortError' });
    expect(reader.getGasPrice).not.toHaveBeenCalled();
  });

  it('does not need a complete provider or signing capability', async () => {
    const reader: EvmFeeReader = fixture();
    await expect(getEvmFeeData(reader)).resolves.toMatchObject({
      maxFeePerGas: 12n,
    });
  });
});

describe('shared successful gas estimate buffer', () => {
  it.each([
    [0n, 0n],
    [1n, 1n],
    [3n, 3n],
    [5n, 6n],
    [21000n, 25200n],
    [21001n, 25201n],
    [50001n, 60001n],
  ])('preserves floor20percent for %s', (estimate, expected) => {
    expect(bufferedEvmGasLimit(estimate)).toBe(expected);
  });
  it('preserves configured minimum semantics including zero and irrelevant negative floor', () => {
    expect(bufferedEvmGasLimit(21000n, 65000n)).toBe(65000n);
    expect(bufferedEvmGasLimit(21000n, 24000n)).toBe(25200n);
    expect(bufferedEvmGasLimit(21000n, 0n)).toBe(25200n);
    expect(bufferedEvmGasLimit(21000n, -1n)).toBe(25200n);
  });
  it('never rounds through Number or overflows fixed-width intermediate arithmetic', () => {
    const estimate = 2n ** 200n + 123n;
    expect(bufferedEvmGasLimit(estimate)).toBe((estimate * 6n) / 5n);
    expect(bufferedEvmGasLimit(estimate, estimate * 2n)).toBe(estimate * 2n);
  });
  it.each([null, undefined, 1, 1.5, '21000', -1n])(
    'rejects invalid estimates %p',
    (value) => {
      expect(() => bufferedEvmGasLimit(value as bigint)).toThrow(
        'Invalid gas estimate'
      );
    }
  );
  it('requires a bigint minimum without coercion', () => {
    expect(() =>
      bufferedEvmGasLimit(21000n, 65000 as unknown as bigint)
    ).toThrow('Invalid gas estimate');
  });
});

describe('shared EVM cancellation fee planning', () => {
  it.each([
    [undefined, 0n, 1n],
    [0n, 1n, 2n],
    [10n, 4n, 12n],
    [4n, 11n, 13n],
  ])(
    'floors the legacy rate and bumps it exactly (%s, %s)',
    (originalGasPrice, currentGasPrice, gasPrice) => {
      expect(
        planEvmCancellationFees({ type: 0, originalGasPrice, currentGasPrice })
      ).toEqual({
        type: 0,
        gasLimit: 42000n,
        gasPrice,
        maximumFee: 42000n * gasPrice,
      });
    }
  );

  it('floors the cap and tip independently before bumping', () => {
    const fee = planEvmCancellationFees({
      type: 2,
      originalMaxFeePerGas: 30n,
      originalMaxPriorityFeePerGas: 1n,
      currentMaxFeePerGas: 20n,
      currentMaxPriorityFeePerGas: 5n,
    });
    expect(fee).toEqual({
      type: 2,
      gasLimit: 42000n,
      maxFeePerGas: 36n,
      maxPriorityFeePerGas: 6n,
      maximumFee: 1512000n,
    });
    expect(Object.isFrozen(fee)).toBe(true);
  });

  it('raises the cap to the selected tip and preserves the one-wei bump', () => {
    expect(
      planEvmCancellationFees({
        type: 2,
        originalMaxPriorityFeePerGas: 4n,
        currentMaxFeePerGas: 2n,
        currentMaxPriorityFeePerGas: 0n,
      })
    ).toEqual({
      type: 2,
      gasLimit: 42000n,
      maxFeePerGas: 5n,
      maxPriorityFeePerGas: 5n,
      maximumFee: 210000n,
    });
  });

  it('plans with current fees when no original rates are available', () => {
    expect(
      planEvmCancellationFees({
        type: 2,
        currentMaxFeePerGas: 3n,
        currentMaxPriorityFeePerGas: 0n,
      })
    ).toEqual({
      type: 2,
      gasLimit: 42000n,
      maxFeePerGas: 4n,
      maxPriorityFeePerGas: 1n,
      maximumFee: 168000n,
    });
  });
});
