import { describe, it, expect, beforeEach, afterEach, vi } from "vitest"
import {
  isNodeEnvironment,
  isBrowserEnvironment,
  isWebWorkerEnvironment,
  getEnvironment,
  EnvironmentError,
  assertNodeEnvironment,
  assertBrowserEnvironment,
} from "./index"

describe("utils - environment detection", () => {
  describe("isNodeEnvironment", () => {
    it("should detect Node.js environment", () => {
      // In Vitest (running in Node), this should be true
      expect(isNodeEnvironment()).toBe(true)
    })

    it("should return false when process is undefined", () => {
      const originalProcess = global.process
      // @ts-ignore
      delete global.process
      expect(isNodeEnvironment()).toBe(false)
      global.process = originalProcess
    })
  })

  describe("isBrowserEnvironment", () => {
    it("should return false in Node environment", () => {
      expect(isBrowserEnvironment()).toBe(false)
    })

    it("should detect browser when window and document exist", () => {
      // @ts-ignore
      global.window = {}
      // @ts-ignore
      global.document = {}
      expect(isBrowserEnvironment()).toBe(true)
      // @ts-ignore
      delete global.window
      // @ts-ignore
      delete global.document
    })
  })

  describe("isWebWorkerEnvironment", () => {
    it("should return false in Node environment", () => {
      expect(isWebWorkerEnvironment()).toBe(false)
    })

    it("should detect web worker environment", () => {
      const originalWindow = global.window
      // @ts-ignore
      delete global.window
      // @ts-ignore
      globalThis.importScripts = () => {}
      expect(isWebWorkerEnvironment()).toBe(true)
      // @ts-ignore
      delete globalThis.importScripts
      // @ts-ignore
      global.window = originalWindow
    })
  })

  describe("getEnvironment", () => {
    it('should return "node" in Node.js', () => {
      expect(getEnvironment()).toBe("node")
    })

    it('should return "browser" when in browser', () => {
      const originalProcess = global.process
      // @ts-ignore
      delete global.process
      // @ts-ignore
      global.window = {}
      // @ts-ignore
      global.document = {}

      expect(getEnvironment()).toBe("browser")

      // @ts-ignore
      delete global.window
      // @ts-ignore
      delete global.document
      global.process = originalProcess
    })

    it('should return "webworker" when in web worker', () => {
      const originalProcess = global.process
      const originalWindow = global.window
      // @ts-ignore
      delete global.process
      // @ts-ignore
      delete global.window
      // @ts-ignore
      globalThis.importScripts = () => {}

      expect(getEnvironment()).toBe("webworker")

      // @ts-ignore
      delete globalThis.importScripts
      global.process = originalProcess
      // @ts-ignore
      global.window = originalWindow
    })

    it('should return "unknown" for unrecognized environment', () => {
      const originalProcess = global.process
      // @ts-ignore
      delete global.process
      expect(getEnvironment()).toBe("unknown")
      global.process = originalProcess
    })
  })

  describe("EnvironmentError", () => {
    it("should create error with correct properties", () => {
      const error = new EnvironmentError("Test message", "node", "browser")
      expect(error.message).toBe("Test message")
      expect(error.name).toBe("EnvironmentError")
      expect(error.requiredEnvironment).toBe("node")
      expect(error.currentEnvironment).toBe("browser")
    })

    it("should be instance of Error", () => {
      const error = new EnvironmentError("Test", "node", "browser")
      expect(error).toBeInstanceOf(Error)
    })
  })

  describe("assertNodeEnvironment", () => {
    it("should not throw in Node.js environment", () => {
      expect(() => assertNodeEnvironment()).not.toThrow()
    })

    it("should throw EnvironmentError when not in Node.js", () => {
      const originalProcess = global.process
      // @ts-ignore
      delete global.process

      expect(() => assertNodeEnvironment()).toThrow(EnvironmentError)
      expect(() => assertNodeEnvironment()).toThrow(
        "This functionality requires Node.js environment"
      )

      global.process = originalProcess
    })
  })

  describe("assertBrowserEnvironment", () => {
    it("should throw in Node.js environment", () => {
      expect(() => assertBrowserEnvironment()).toThrow(EnvironmentError)
      expect(() => assertBrowserEnvironment()).toThrow(
        "This functionality requires browser environment"
      )
    })

    it("should not throw when window and document exist", () => {
      // @ts-ignore
      global.window = {}
      // @ts-ignore
      global.document = {}

      expect(() => assertBrowserEnvironment()).not.toThrow()

      // @ts-ignore
      delete global.window
      // @ts-ignore
      delete global.document
    })
  })
})
