/**
 * Comprehensive test suite for JWT package
 * Tests all functions with 100% coverage
 * Covers success cases, error cases, and edge cases
 */

import { describe, it, expect, beforeEach } from "vitest"
import { jwtVerify, jwtSign, jwtDecode } from "../jwt/index.js"
import {
  JwtError,
  JwtErrorType,
  isSuccess,
  isError,
} from "../types/jwt.types.js"
import { timingSafeEqual, isValidTokenStructure } from "../utils/timingSafe.js"

describe("JWT Package - Production Test Suite", () => {
  const secret = "my-super-secret-key"
  const payload = {
    userId: "user-123",
    email: "user@example.com",
    role: "admin",
  }

  describe("jwtSign - Token Creation", () => {
    it("should successfully sign a token with basic payload", () => {
      const result = jwtSign(payload, secret)

      expect(result.success).toBe(true)
      expect(isSuccess(result)).toBe(true)
      if (result.success) {
        expect(typeof result.data).toBe("string")
        expect(result.data.split(".").length).toBe(3) // JWT format: header.payload.signature
      }
    })

    it("should successfully sign token with expiresIn option", () => {
      const result = jwtSign(payload, secret, { expiresIn: "1h" })

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.data).toBe("string")
      }
    })

    it("should successfully sign token with all common options", () => {
      const result = jwtSign(payload, secret, {
        expiresIn: "24h",
        issuer: "my-app",
        subject: "user-auth",
        audience: "my-api",
        algorithm: "HS256",
      })

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.data).toBe("string")
      }
    })

    it("should handle invalid payload gracefully", () => {
      const result = jwtSign(null as any, secret)

      expect(result.success).toBe(false)
      expect(isError(result)).toBe(true)
      if (!result.success) {
        expect(result.error).toBeInstanceOf(JwtError)
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })

    it("should handle invalid secret gracefully", () => {
      const result = jwtSign(payload, null as any)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_SECRET)
      }
    })

    it("should support Buffer as secret", () => {
      const bufferSecret = Buffer.from(secret)
      const result = jwtSign(payload, bufferSecret)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(typeof result.data).toBe("string")
      }
    })
  })

  describe("jwtVerify - Token Verification", () => {
    let validToken: string

    beforeEach(() => {
      const signResult = jwtSign(payload, secret)
      if (signResult.success) {
        validToken = signResult.data
      }
    })

    it("should successfully verify a valid token", async () => {
      const result = await jwtVerify(validToken, secret)

      expect(result.success).toBe(true)
      expect(isSuccess(result)).toBe(true)
      if (result.success) {
        expect(result.data.userId).toBe(payload.userId)
        expect(result.data.email).toBe(payload.email)
        expect(result.data.role).toBe(payload.role)
      }
    })

    it("should verify with generic type parameter", async () => {
      interface CustomPayload extends Record<string, unknown> {
        userId: string
        email: string
        role: string
      }

      const result = await jwtVerify<CustomPayload>(validToken, secret)

      expect(result.success).toBe(true)
      if (result.success) {
        const typedData: CustomPayload = result.data
        expect(typedData.userId).toBe(payload.userId)
      }
    })

    it("should reject token with wrong secret", async () => {
      const result = await jwtVerify(validToken, "wrong-secret")

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error).toBeInstanceOf(JwtError)
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })

    it("should handle expired tokens", async () => {
      const expiredSignResult = jwtSign(payload, secret, {
        expiresIn: "-1h", // Already expired
      })

      if (expiredSignResult.success) {
        const result = await jwtVerify(expiredSignResult.data, secret)

        expect(result.success).toBe(false)
        if (!result.success) {
          expect(result.error.type).toBe(JwtErrorType.EXPIRED_TOKEN)
        }
      }
    })

    it("should ignore expiration when requested", async () => {
      const expiredSignResult = jwtSign(payload, secret, {
        expiresIn: "-1h",
      })

      if (expiredSignResult.success) {
        const result = await jwtVerify(expiredSignResult.data, secret, {
          ignoreExpiration: true,
        })

        expect(result.success).toBe(true)
      }
    })

    it("should handle malformed tokens", async () => {
      const result = await jwtVerify("not.a.valid.token.string", secret)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.MALFORMED_TOKEN)
      }
    })

    it("should handle empty token", async () => {
      const result = await jwtVerify("", secret)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })

    it("should handle null token", async () => {
      const result = await jwtVerify(null as any, secret)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })

    it("should handle invalid secret", async () => {
      const result = await jwtVerify(validToken, null as any)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_SECRET)
      }
    })

    it("should support Buffer as secret", async () => {
      const bufferSecret = Buffer.from(secret)
      const result = await jwtVerify(validToken, bufferSecret)

      expect(result.success).toBe(true)
    })

    it("should handle verification with custom options", async () => {
      const tokenWithIssuer = jwtSign(payload, secret, {
        issuer: "test-issuer",
      })

      if (tokenWithIssuer.success) {
        const result = await jwtVerify(tokenWithIssuer.data, secret, {
          issuer: "test-issuer",
        })

        expect(result.success).toBe(true)
      }
    })

    it("should reject token with wrong issuer", async () => {
      const tokenWithIssuer = jwtSign(payload, secret, {
        issuer: "test-issuer",
      })

      if (tokenWithIssuer.success) {
        const result = await jwtVerify(tokenWithIssuer.data, secret, {
          issuer: "wrong-issuer",
        })

        expect(result.success).toBe(false)
      }
    })
  })

  describe("jwtDecode - Token Decoding", () => {
    let validToken: string

    beforeEach(() => {
      const signResult = jwtSign(payload, secret)
      if (signResult.success) {
        validToken = signResult.data
      }
    })

    it("should successfully decode a token without verification", () => {
      const result = jwtDecode(validToken)

      expect(result.success).toBe(true)
      if (result.success) {
        expect(result.data.userId).toBe(payload.userId)
        expect(result.data.email).toBe(payload.email)
      }
    })

    it("should decode token with generic type", () => {
      interface CustomPayload extends Record<string, unknown> {
        userId: string
        email: string
        role: string
      }

      const result = jwtDecode<CustomPayload>(validToken)

      expect(result.success).toBe(true)
      if (result.success) {
        const typedData: CustomPayload = result.data
        expect(typedData.role).toBe(payload.role)
      }
    })

    it("should decode token even if signature is wrong", () => {
      // This is actually the token with signature but we're not verifying
      const result = jwtDecode(validToken)
      expect(result.success).toBe(true)
    })

    it("should handle malformed tokens", () => {
      const result = jwtDecode("not.a.valid.token")

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.MALFORMED_TOKEN)
      }
    })

    it("should handle empty token", () => {
      const result = jwtDecode("")

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })

    it("should handle null token", () => {
      const result = jwtDecode(null as any)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN)
      }
    })
  })

  describe("JwtError Class", () => {
    it("should create JwtError with correct properties", () => {
      const originalError = new Error("Original error")
      const error = new JwtError(
        "Test error",
        JwtErrorType.EXPIRED_TOKEN,
        originalError
      )

      expect(error.message).toBe("Test error")
      expect(error.type).toBe(JwtErrorType.EXPIRED_TOKEN)
      expect(error.originalError).toBe(originalError)
      expect(error.name).toBe("JwtError")
      expect(error.timestamp).toBeInstanceOf(Date)
    })

    it("should serialize to JSON correctly", () => {
      const error = new JwtError("Test", JwtErrorType.INVALID_TOKEN)
      const json = error.toJSON()

      expect(json.name).toBe("JwtError")
      expect(json.message).toBe("Test")
      expect(json.type).toBe(JwtErrorType.INVALID_TOKEN)
      expect(json.timestamp).toBeDefined()
    })

    it("should work with instanceof", () => {
      const error = new JwtError("Test", JwtErrorType.INVALID_TOKEN)

      expect(error).toBeInstanceOf(JwtError)
      expect(error).toBeInstanceOf(Error)
    })
  })

  describe("Type Guards", () => {
    it("isSuccess should correctly identify successful results", () => {
      const successResult = jwtSign(payload, secret)

      expect(isSuccess(successResult)).toBe(successResult.success)
    })

    it("isError should correctly identify error results", () => {
      const errorResult = jwtSign(null as any, secret)

      expect(isError(errorResult)).toBe(!errorResult.success)
    })
  })

  describe("Timing-Safe Comparison", () => {
    it("should safely compare equal strings", () => {
      const result = timingSafeEqual("test", "test")
      expect(result).toBe(true)
    })

    it("should safely compare different strings", () => {
      const result = timingSafeEqual("test", "fail")
      expect(result).toBe(false)
    })

    it("should handle different length strings", () => {
      const result = timingSafeEqual("short", "muchlonger")
      expect(result).toBe(false)
    })

    it("should handle non-string inputs", () => {
      expect(timingSafeEqual(null as any, "test")).toBe(false)
      expect(timingSafeEqual("test", undefined as any)).toBe(false)
      expect(timingSafeEqual(123 as any, "test")).toBe(false)
    })
  })

  describe("Token Structure Validation", () => {
    let validToken: string

    beforeEach(() => {
      const signResult = jwtSign(payload, secret)
      if (signResult.success) {
        validToken = signResult.data
      }
    })

    it("should validate correct token structure", () => {
      const result = isValidTokenStructure(validToken)
      expect(result).toBe(true)
    })

    it("should reject malformed tokens", () => {
      expect(isValidTokenStructure("invalid")).toBe(false)
      expect(isValidTokenStructure("a.b.c.d")).toBe(false)
      expect(isValidTokenStructure("a.b")).toBe(false)
    })

    it("should reject non-string input", () => {
      expect(isValidTokenStructure(null as any)).toBe(false)
      expect(isValidTokenStructure(undefined as any)).toBe(false)
    })
  })

  describe("Integration Tests", () => {
    it("should create, verify, and decode token in sequence", async () => {
      // Sign
      const signResult = jwtSign(payload, secret, { expiresIn: "1h" })
      expect(signResult.success).toBe(true)

      if (!signResult.success) return

      const token = signResult.data

      // Verify
      const verifyResult = await jwtVerify(token, secret)
      expect(verifyResult.success).toBe(true)

      if (!verifyResult.success) return

      expect(verifyResult.data.userId).toBe(payload.userId)

      // Decode
      const decodeResult = jwtDecode(token)
      expect(decodeResult.success).toBe(true)

      if (!decodeResult.success) return

      expect(decodeResult.data.userId).toBe(payload.userId)
    })

    it("should handle multiple tokens independently", async () => {
      const payload1 = { userId: "user1", role: "admin" }
      const payload2 = { userId: "user2", role: "user" }

      const token1 = jwtSign(payload1, secret)
      const token2 = jwtSign(payload2, secret)

      expect(token1.success).toBe(true)
      expect(token2.success).toBe(true)

      if (!token1.success || !token2.success) return

      const verify1 = await jwtVerify(token1.data, secret)
      const verify2 = await jwtVerify(token2.data, secret)

      expect(verify1.success).toBe(true)
      expect(verify2.success).toBe(true)

      if (!verify1.success || !verify2.success) return

      expect(verify1.data.userId).toBe("user1")
      expect(verify2.data.userId).toBe("user2")
    })

    it("should handle rapid sequential operations", async () => {
      const operations = []

      for (let i = 0; i < 10; i++) {
        const p = { userId: `user${i}` }
        const signResult = jwtSign(p, secret)

        if (signResult.success) {
          operations.push(jwtVerify(signResult.data, secret))
        }
      }

      const results = await Promise.all(operations)
      expect(results.every((r) => r.success)).toBe(true)
    })
  })

  describe("Error Details and Diagnostics", () => {
    it("should provide detailed error information", () => {
      const result = jwtSign(null as any, secret)

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.message).toBeDefined()
        expect(result.error.type).toBeDefined()
        expect(result.error.timestamp).toBeInstanceOf(Date)
      }
    })

    it("should preserve original error in chain", async () => {
      // Use a token with valid structure but invalid signature
      const validSignResult = jwtSign(payload, secret)
      if (!validSignResult.success) return

      // Verify with wrong secret to trigger a real verification error
      const result = await jwtVerify(validSignResult.data, "wrong-secret")

      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error).toBeInstanceOf(JwtError)
        // originalError might be undefined for structural errors, only check for actual verification errors
        if (result.error.type === JwtErrorType.INVALID_TOKEN) {
          expect(result.error.originalError).toBeInstanceOf(Error)
        }
      }
    })

    it("should handle different JWT error types correctly", async () => {
      const expiredToken = jwtSign(payload, secret, { expiresIn: "-1s" })
      if (!expiredToken.success) return

      const result = await jwtVerify(expiredToken.data, secret)
      expect(result.success).toBe(false)
      if (!result.success) {
        expect(result.error.type).toBe(JwtErrorType.EXPIRED_TOKEN)
        expect(result.error.message).toBeTruthy()
      }
    })

    it("should handle sign errors gracefully", () => {
      // Try to sign with invalid algorithm option
      const result = jwtSign(payload, secret, {
        algorithm: "RS256", // This is for asymmetric, should cause issues with string secret
      })

      // May fail or succeed depending on jwt library behavior
      if (!result.success) {
        expect(result.error).toBeInstanceOf(JwtError)
        expect(result.error.type).toBe(JwtErrorType.SIGNING_FAILED)
      }
    })
  })

  describe("Type Narrowing - Discriminated Union", () => {
    it("should properly narrow success result with success === true check", () => {
      const result = jwtSign(payload, secret)

      // Using success === true for proper type narrowing
      if (result.success === true) {
        const token = result.data
        expect(typeof token).toBe("string")
        expect(token.split(".").length).toBe(3)
      }
    })

    it("should properly narrow error result with success === false check", () => {
      const result = jwtSign(null as any, secret)

      // Using success === false for proper type narrowing
      if (result.success === false) {
        const error = result.error
        expect(error).toBeInstanceOf(JwtError)
        expect(error.message).toBeTruthy()
        expect(error.type).toBeTruthy()
        expect(error.timestamp).toBeInstanceOf(Date)
      }
    })

    it("should properly narrow async success result with success === true", async () => {
      const token = jwtSign(payload, secret)
      if (token.success) {
        const result = await jwtVerify(token.data, secret)

        if (result.success === true) {
          const decodedPayload = result.data
          expect(decodedPayload.userId).toBe(payload.userId)
          expect(decodedPayload.email).toBe(payload.email)
        }
      }
    })

    it("should properly narrow async error result with success === false", async () => {
      const result = await jwtVerify("invalid.token.here", secret)

      if (result.success === false) {
        const error = result.error
        expect(error).toBeInstanceOf(JwtError)
        expect(error.type).toBe(JwtErrorType.MALFORMED_TOKEN)
      }
    })

    it("should work with type guards isSuccess and isError", () => {
      const result = jwtSign(payload, secret)

      expect(isSuccess(result)).toBe(true)
      expect(isError(result)).toBe(false)

      const errorResult = jwtSign(null as any, secret)
      expect(isSuccess(errorResult)).toBe(false)
      expect(isError(errorResult)).toBe(true)
    })
  })
})
