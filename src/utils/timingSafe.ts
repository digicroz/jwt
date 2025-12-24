/**
 * Timing-safe utility functions
 * Protects against timing attacks on JWT verification
 */

/**
 * Constant-time string comparison to prevent timing attacks
 * Uses subtle.timingSafeEqual for cryptographic comparison
 * Falls back to safe implementation if needed
 *
 * @param a First string to compare
 * @param b Second string to compare
 * @returns true if strings are equal, false otherwise
 */
export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") {
    return false
  }

  if (a.length !== b.length) {
    return false
  }

  try {
    const crypto = require("crypto")
    const bufferA = Buffer.from(a)
    const bufferB = Buffer.from(b)
    return crypto.timingSafeEqual(bufferA, bufferB)
  } catch {
    let result = 0
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i)
    }
    return result === 0
  }
}

/**
 * Safely parse JWT token structure
 * Prevents errors from malformed tokens
 *
 * @param token JWT token to parse
 * @returns Object with header, payload, and signature or null if invalid
 */
export function parseTokenStructure(token: string): {
  header: string
  payload: string
  signature: string
} | null {
  if (typeof token !== "string") {
    return null
  }

  const parts = token.split(".")

  if (parts.length !== 3) {
    return null
  }

  return {
    header: parts[0],
    payload: parts[1],
    signature: parts[2],
  }
}

/**
 * Safely decode base64url string
 * Handles padding and errors gracefully
 *
 * @param str Base64url string to decode
 * @returns Decoded string or null if invalid
 */
export function safeBase64UrlDecode(str: string): string | null {
  try {
    if (typeof str !== "string") {
      return null
    }

    // Add padding if needed
    let padded = str
    const padding = 4 - (str.length % 4)
    if (padding && padding !== 4) {
      padded = str + "=".repeat(padding)
    }

    // Replace URL-safe characters
    const decoded = Buffer.from(padded, "base64").toString("utf-8")
    return decoded
  } catch {
    return null
  }
}

/**
 * Validate token structure without verification
 * Quick structural validation
 *
 * @param token JWT token to validate
 * @returns true if token has valid structure
 */
export function isValidTokenStructure(token: string): boolean {
  const parsed = parseTokenStructure(token)
  if (!parsed) {
    return false
  }

  // Try to decode payload to ensure it's valid base64url
  const payload = safeBase64UrlDecode(parsed.payload)
  if (!payload) {
    return false
  }

  // Try to parse as JSON
  try {
    JSON.parse(payload)
    return true
  } catch {
    return false
  }
}
