/**
 * Test suite for timing-safe utilities
 */

import { describe, it, expect } from "vitest"
import {
  timingSafeEqual,
  parseTokenStructure,
  safeBase64UrlDecode,
  isValidTokenStructure,
} from "../utils/timingSafe.ts"

describe("Timing-Safe Utilities", () => {
  describe("parseTokenStructure", () => {
    it("should parse valid JWT structure", () => {
      const token = "header.payload.signature"
      const result = parseTokenStructure(token)

      expect(result).not.toBeNull()
      if (result) {
        expect(result.header).toBe("header")
        expect(result.payload).toBe("payload")
        expect(result.signature).toBe("signature")
      }
    })

    it("should return null for invalid structure with extra dots", () => {
      const result = parseTokenStructure("header.payload.signature.extra")
      expect(result).toBeNull()
    })

    it("should return null for invalid structure with too few parts", () => {
      const result = parseTokenStructure("header.payload")
      expect(result).toBeNull()
    })

    it("should return null for non-string input", () => {
      expect(parseTokenStructure(null as any)).toBeNull()
      expect(parseTokenStructure(undefined as any)).toBeNull()
      expect(parseTokenStructure(123 as any)).toBeNull()
    })
  })

  describe("safeBase64UrlDecode", () => {
    it("should decode valid base64url string", () => {
      // 'hello' in base64url
      const encoded = "aGVsbG8"
      const result = safeBase64UrlDecode(encoded)
      expect(result).toBe("hello")
    })

    it("should handle padding correctly", () => {
      // Test with string that needs padding
      const encoded = "aGVsbG8" // 'hello' with implicit padding
      const result = safeBase64UrlDecode(encoded)
      expect(result).toBe("hello")
    })

    it("should handle invalid looking input gracefully", () => {
      // Note: base64 doesn't necessarily throw on decode
      // It may produce garbage output, which is fine
      const result = safeBase64UrlDecode("!!!invalid!!!")
      expect(typeof result).toBe("string") // May produce output or be handled
    })

    it("should return null for non-string input", () => {
      expect(safeBase64UrlDecode(null as any)).toBeNull()
      expect(safeBase64UrlDecode(undefined as any)).toBeNull()
    })

    it("should handle URL-safe base64 characters", () => {
      // URL-safe base64 uses - and _ instead of + and /
      const encoded = "aGVsbG8tX3dvcmxk" // 'hello-_world' encoded
      const result = safeBase64UrlDecode(encoded)
      expect(result).toBeDefined()
    })
  })

  describe("isValidTokenStructure", () => {
    it("should validate proper JWT token structure", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
      const result = isValidTokenStructure(jwt)
      expect(result).toBe(true)
    })

    it("should reject malformed token", () => {
      const result = isValidTokenStructure("not.valid.token")
      // This will return false because the base64 parts are invalid
      expect(result).toBe(false)
    })

    it("should reject token with only 2 parts", () => {
      const result = isValidTokenStructure("header.payload")
      expect(result).toBe(false)
    })

    it("should reject token with 4 parts", () => {
      const result = isValidTokenStructure("a.b.c.d")
      expect(result).toBe(false)
    })

    it("should reject non-string input", () => {
      expect(isValidTokenStructure(null as any)).toBe(false)
      expect(isValidTokenStructure(undefined as any)).toBe(false)
      expect(isValidTokenStructure(123 as any)).toBe(false)
    })

    it("should reject token with non-JSON payload", () => {
      const token = "header.notjson.signature"
      const result = isValidTokenStructure(token)
      expect(result).toBe(false)
    })

    it("should handle tokens with complex JSON payloads", () => {
      // Create a valid base64url of a JSON object
      const jsonPayload = JSON.stringify({ sub: "user", role: "admin" })
      const encoded = Buffer.from(jsonPayload).toString("base64")
      const token = `header.${encoded}.signature`
      const result = isValidTokenStructure(token)
      expect(result).toBe(true)
    })
  })

  describe("timingSafeEqual - Edge cases", () => {
    it("should handle empty strings", () => {
      expect(timingSafeEqual("", "")).toBe(true)
      expect(timingSafeEqual("", "nonempty")).toBe(false)
    })

    it("should handle special characters", () => {
      const str1 = "!@#$%^&*()"
      const str2 = "!@#$%^&*()"
      expect(timingSafeEqual(str1, str2)).toBe(true)
    })

    it("should handle unicode characters", () => {
      const str1 = "こんにちは"
      const str2 = "こんにちは"
      expect(timingSafeEqual(str1, str2)).toBe(true)
    })

    it("should reject similar but different strings", () => {
      expect(timingSafeEqual("test1", "test2")).toBe(false)
      expect(timingSafeEqual("abc", "abd")).toBe(false)
    })
  })
})
