export default {
  clearMocks: true,
  collectCoverage: true,
  coverageDirectory: "coverage",
  coverageProvider: "babel",
  coverageReporters: ["json", "text", "lcov", "clover"],
  
  // Configure Babel transform
  transform: {
    "^.+\\.js$": "babel-jest"
  },
  
  testEnvironment: 'node',
  moduleFileExtensions: ["js", "jsx", "json", "node"],
  
  testMatch: [
    "**/__tests__/**/*.[jt]s?(x)",
    "**/?(*.)+(spec|test).[jt]s?(x)"
  ],
testPathIgnorePatterns: ["/node_modules/", "/dist/"],
coveragePathIgnorePatterns: ["/node_modules/", "/dist/"],
modulePathIgnorePatterns: ["/dist/"],
};