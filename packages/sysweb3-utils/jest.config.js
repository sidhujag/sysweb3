module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx'],
  transform: {
    '^.+\\.(ts|tsx)$': [
      'ts-jest',
      {
        isolatedModules: true,
      },
    ],
  },
  testMatch: ['**/test/**/*.spec.ts'],
  moduleNameMapper: {
    '^@syscoin/sysweb3-network$': '<rootDir>/../sysweb3-network/src',
    '^@syscoin/sysweb3-core$': '<rootDir>/../sysweb3-core/src',
    '^@syscoin/sysweb3-keyring$': '<rootDir>/../sysweb3-keyring/src',
    'isomorphic-fetch': '<rootDir>/../../__mocks__/isomorphic-fetch.js',
  },
  setupFilesAfterEnv: [
    '<rootDir>/../../jest.setup.js',
    '<rootDir>/test/setup.ts',
  ],
};
