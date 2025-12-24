/**
 * Environment detection utilities
 */

/**
 * Determines if the current environment is Node.js
 * @returns true if running in Node.js, false otherwise
 */
export function isNodeEnvironment(): boolean {
  return (
    typeof process !== "undefined" &&
    process.versions != null &&
    process.versions.node != null
  );
}

/**
 * Determines if the current environment is a browser
 * @returns true if running in a browser, false otherwise
 */
export function isBrowserEnvironment(): boolean {
  return typeof window !== "undefined" && typeof document !== "undefined";
}

/**
 * Determines if the current environment is a web worker
 * @returns true if running in a web worker, false otherwise
 */
export function isWebWorkerEnvironment(): boolean {
  return (
    typeof (globalThis as any).importScripts === "function" &&
    typeof window === "undefined"
  );
}

/**
 * Gets the current runtime environment
 * @returns 'node' | 'browser' | 'webworker' | 'unknown'
 */
export function getEnvironment(): "node" | "browser" | "webworker" | "unknown" {
  if (isNodeEnvironment()) return "node";
  if (isBrowserEnvironment()) return "browser";
  if (isWebWorkerEnvironment()) return "webworker";
  return "unknown";
}

/**
 * Error thrown when functionality is not supported in the current environment
 */
export class EnvironmentError extends Error {
  constructor(
    message: string,
    public readonly requiredEnvironment: string,
    public readonly currentEnvironment: string
  ) {
    super(message);
    this.name = "EnvironmentError";
  }
}

/**
 * Asserts that the current environment is Node.js
 * @throws {EnvironmentError} if not running in Node.js
 */
export function assertNodeEnvironment(): void {
  if (!isNodeEnvironment()) {
    throw new EnvironmentError(
      "This functionality requires Node.js environment",
      "node",
      getEnvironment()
    );
  }
}

/**
 * Asserts that the current environment is a browser
 * @throws {EnvironmentError} if not running in a browser
 */
export function assertBrowserEnvironment(): void {
  if (!isBrowserEnvironment()) {
    throw new EnvironmentError(
      "This functionality requires browser environment",
      "browser",
      getEnvironment()
    );
  }
}
