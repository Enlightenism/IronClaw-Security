// frontend/jest.config.cjs
const path = require("path");

module.exports = {
  testEnvironment: "jsdom",

  setupFilesAfterEnv: ["<rootDir>/src/setupTests.js"],

  transform: {
    "^.+\\.[jt]sx?$": "babel-jest",
  },

  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
    "\\.(css|less|scss|sass)$": "<rootDir>/src/__mocks__/fileMock.js",
    "\\.(gif|ttf|eot|svg|png|jpg|jpeg|webp|avif)$":
      "<rootDir>/src/__mocks__/fileMock.js",
  },

  testMatch: [
    "<rootDir>/src/**/__tests__/**/*.[jt]s?(x)",
    "<rootDir>/src/**/*.{test,spec}.[jt]s?(x)",
  ],

  testPathIgnorePatterns: ["/node_modules/", "/build/", "/dist/"],

  collectCoverageFrom: [
    "src/**/*.{js,jsx}",
    "!src/**/*.{test,spec}.{js,jsx}",
    "!src/__mocks__/**",
    "!src/setupTests.js",
    "!src/index.js",
  ],

  moduleFileExtensions: ["js", "jsx", "json", "node"],

  modulePaths: [path.resolve(__dirname, "src")],

  watchPlugins: [],
};
