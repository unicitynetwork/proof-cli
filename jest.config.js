// Load the developer's .env here, in the real process, so UNICITY_TEST_API_KEY reaches the e2e
// suite. Test files run in a sandbox whose process.env is a copy taken from this process.
try {
  process.loadEnvFile();
} catch (error) {
  if (error.code !== 'ENOENT') {
    throw error;
  }
}

export default {
  collectCoverage: process.env.CI === 'true',
  collectCoverageFrom: ['<rootDir>/src/**/*.ts'],
  extensionsToTreatAsEsm: ['.ts'],
  setupFilesAfterEnv: ['<rootDir>/tests/support/cleanup.ts'],
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  testEnvironment: 'node',
  testMatch: ['<rootDir>/tests/**/*Test.ts'],
  transform: {
    '^.+\\.[tj]sx?$': 'babel-jest',
  },
  // The SDK and the noble libraries ship ESM only; babel-jest must transform them for the CJS test runtime.
  transformIgnorePatterns: ['/node_modules/(?!(uuid|@noble|@unicitylabs)/)'],
};
