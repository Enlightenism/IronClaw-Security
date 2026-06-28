// frontend/jest.config.js
const path = require("path");

module.exports = {
  testEnvironment: "jsdom",

  setupFilesAfterFramework: ["<rootDir>/src/setupTests.js"],

  // Transform JSX and modern JS via babel-jest (bundled with react-scripts)
  transform: {
    "^.+\\.[jt]sx?$": "babel-jest",
  },

  // Resolve @/ alias — mirrors craco.config.js webpack alias
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
    // Silence CSS / asset imports inside components
    "\\.(css|less|scss|sass)$": "<rootDir>/src/__mocks__/fileMock.js",
    "\\.(gif|ttf|eot|svg|png|jpg|jpeg|webp|avif)$":
      "<rootDir>/src/__mocks__/fileMock.js",
  },

  // Only match test files inside src/
  testMatch: [
    "<rootDir>/src/**/__tests__/**/*.[jt]s?(x)",
    "<rootDir>/src/**/*.{test,spec}.[jt]s?(x)",
  ],

  // Ignore build artefacts and node_modules
  testPathIgnorePatterns: ["/node_modules/", "/build/", "/dist/"],

  // Collect coverage from src, excluding test files and mocks
  collectCoverageFrom: [
    "src/**/*.{js,jsx}",
    "!src/**/*.{test,spec}.{js,jsx}",
    "!src/__mocks__/**",
    "!src/setupTests.js",
    "!src/index.js",
  ],

  // Map module extensions in resolution order
  moduleFileExtensions: ["js", "jsx", "json", "node"],

  // Absolute module directories
  modulePaths: [path.resolve(__dirname, "src")],

  // Prevent test runs from opening a browser
  watchPlugins: [],
};
