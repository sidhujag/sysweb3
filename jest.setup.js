// Mock fetch globally
global.fetch = require('isomorphic-fetch');

// Mock localStorage for browser-like environments
global.localStorage = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
};

// Mock crypto for tests
global.crypto = {
  randomBytes: (size) => Buffer.alloc(size, 1),
  getRandomValues: (buffer) => {
    for (let i = 0; i < buffer.length; i++) {
      buffer[i] = Math.floor(Math.random() * 256);
    }
    return buffer;
  },
};

// Suppress console errors during tests unless explicitly needed
const originalError = console.error;
beforeAll(() => {
  console.error = (...args) => {
    if (
      typeof args[0] === 'string' &&
      (args[0].includes('Consider adding an error boundary') ||
        args[0].includes('Warning:') ||
        args[0].includes('act()'))
    ) {
      return;
    }
    originalError.call(console, ...args);
  };
});

afterAll(() => {
  console.error = originalError;
});

// Mock sysweb3 storage
jest.mock('@sidhujag/sysweb3-core', () => {
  const mockStorage = {
    vault: null,
    set: jest.fn((key, value) => {
      mockStorage[key] = value;
      return Promise.resolve();
    }),
    get: jest.fn((key) => {
      return Promise.resolve(mockStorage[key]);
    }),
    remove: jest.fn((key) => {
      delete mockStorage[key];
      return Promise.resolve();
    }),
    clear: jest.fn(() => {
      Object.keys(mockStorage).forEach((key) => {
        if (
          key !== 'set' &&
          key !== 'get' &&
          key !== 'remove' &&
          key !== 'clear'
        ) {
          delete mockStorage[key];
        }
      });
      return Promise.resolve();
    }),
  };

  return {
    sysweb3Di: {
      getStateStorageDb: () => mockStorage,
    },
  };
});
