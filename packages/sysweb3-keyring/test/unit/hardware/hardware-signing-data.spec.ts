import { captureHardwareSigningData } from '../../../src/hardware-signing-data';

const invalid = () => new Error('Invalid signing data');
const capture = (value: unknown) => captureHardwareSigningData(value, invalid);

test('captures ordinary wide EIP712 records, exact integers and bytes immutably', () => {
  const input = {
    types: { Entry: [{ name: 'amount', type: 'uint256' }] },
    message: {
      entries: Array.from({ length: 1000 }, (_, index) => ({
        amount: BigInt(index),
      })),
      maximum: (1n << 256n) - 1n,
      minimum: -(1n << 255n),
      bytes: Uint8Array.from([0, 255]),
      text: 'A Unicode message 雪',
    },
  };
  const owned = capture(input);
  input.message.entries[0].amount = 99n;
  input.message.bytes[0] = 2;
  expect(owned.message.entries[0]).toEqual({ amount: '0' });
  expect(owned.message.maximum).toBe(((1n << 256n) - 1n).toString());
  expect(owned.message.minimum).toBe((-(1n << 255n)).toString());
  expect(owned.message.bytes).toBe('0x00ff');
  expect(owned.message.text).toBe('A Unicode message 雪');
  expect(Object.isFrozen(owned.message.entries[0])).toBe(true);
});

test('bounds expanded work for repeated noncyclic DAG references', () => {
  let input: unknown = { text: 'leaf' };
  for (let count = 0; count < 40; count++)
    input = { left: input, right: input };
  expect(() => capture(input)).toThrow('Invalid signing data');
});

test.each([
  [
    'a wide object',
    () =>
      Object.fromEntries(
        Array.from({ length: 17000 }, (_, i) => [String(i), undefined])
      ),
  ],
  ['oversized UTF8', () => '雪'.repeat(350000)],
  ['oversized encoded bytes', () => new Uint8Array(524288)],
  ['oversized integer', () => 1n << 100000n],
  ['sparse array length', () => new Array(1000000)],
  ['sparse small array', () => Object.assign(new Array(2), { 1: 'value' })],
  ['undefined array entry', () => [undefined]],
  [
    'array named properties',
    () => Object.assign(['value'], { extra: 'hidden from JSON' }),
  ],
])('refuses %s within the single shared capture boundary', (_name, input) => {
  expect(() => capture(input())).toThrow('Invalid signing data');
});
