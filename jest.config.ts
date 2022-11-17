import type { Config } from "jest";

type ArrayElement<MyArray> = MyArray extends Array<infer T> ? T : never;

const baseConfig: ArrayElement<NonNullable<Config["projects"]>> = {
  roots: ["<rootDir>"],
  testMatch: ["**/*.spec.ts"],
  // This combination of preset/transformIgnorePatterns enforces that both TS and
  // JS files are transformed to CJS, and that the transform also applies to the
  // dependencies in the node_modules, so that ESM-only dependencies are supported.
  preset: "ts-jest/presets/js-with-ts",
  // deliberately set to an empty array to allow including node_modules when transforming code:
  transformIgnorePatterns: [],
  modulePathIgnorePatterns: ["dist/", "<rootDir>/examples/"],
  coveragePathIgnorePatterns: [
    ".*.spec.ts",
    "dist/"
  ],
  clearMocks: true,
  injectGlobals: false,
  setupFilesAfterEnv: ['<rootDir>/jest.setup.ts'],
}

// Required by @peculiar/webcrypto, which comes from the polyfills
// loaded in the setup file.
process.env.OPENSSL_CONF = "/dev/null";

export default {
  reporters: ["default", "github-actions"],
  collectCoverage: true,
  coverageReporters: process.env.CI ? ["text", "lcov"] : ["text"],
  coverageThreshold: {
    global: {
      branches: 100,
      functions: 100,
      lines: 100,
      statements: 100,
    },
  },
  collectCoverageFrom: [
    "<rootDir>/src/**/*.ts",
  ],
  projects: [{
    ...baseConfig,
    displayName: "core",
    roots: ["<rootDir>/packages/core"],
  }, {
    ...baseConfig,
    displayName: "oidc-browser",
    roots: ["<rootDir>/packages/oidc-browser"],
    // This test environment is an extension of jsdom. This module targets the
    // browser environment only, so tests only need to run in jsdom.
    // Currently, this is still required despite the polyfills in jest setup.
    // See comments in file.
    testEnvironment: "<rootDir>/tests/environment/customEnvironment.ts",
  }, {
    ...baseConfig,
    displayName: "browser",
    roots: ["<rootDir>/packages/browser"],
    // This test environment is an extension of jsdom. This module targets the
    // browser environment only, so tests only need to run in jsdom.
    // Currently, this is still required despite the polyfills in jest setup.
    // See comments in file.
    testEnvironment: "<rootDir>/tests/environment/customEnvironment.ts",
    // Enable injectGlobals here to support jest-mock-console
    // https://github.com/bpedersen/jest-mock-console/issues/32
    injectGlobals: true,
  }, {
    ...baseConfig,
    displayName: "node",
    roots: ["<rootDir>/packages/node"],
    testEnvironment: "node",
  }, {
    ...baseConfig, 
    displayName: "e2e-node",
    roots: ["<rootDir>/e2e/node"],
    setupFiles: ["<rootDir>/jest.e2e.setup.ts"],
    slowTestThreshold: 30,
  }],
} as Config;