/**
 * iam-lib entry point.
 *
 *   import { createIamHandlers, createTokenService, setSettingsProvider } from "iam-lib";
 *
 * See README.md and docs/CONFIGURATION.md.
 */

export * from "./src/index.js";

// Optional process-wide IAM instance, for code that cannot receive the handler
// set through its constructor. Prefer passing the instance explicitly.
let iamInstance = null;

/**
 * @param {object} handlers the object returned by createIamHandlers()
 */
export function initializeIAM(handlers) {
  iamInstance = handlers;
  return iamInstance;
}

export function getIAM() {
  if (!iamInstance) {
    throw new Error("IAM not initialized. Call initializeIAM() first.");
  }
  return iamInstance;
}
