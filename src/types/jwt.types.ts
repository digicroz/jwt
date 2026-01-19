
import type { VerifyOptions, SignOptions, DecodeOptions } from "jsonwebtoken"
import type { StdResponse } from "@digicroz/js-kit/std-response"

/**
 * JWT Error types - Production-level error categorization
 */
export enum JwtErrorType {
  INVALID_TOKEN = "INVALID_TOKEN",
  EXPIRED_TOKEN = "EXPIRED_TOKEN",
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  MALFORMED_TOKEN = "MALFORMED_TOKEN",
  INVALID_ALGORITHM = "INVALID_ALGORITHM",
  VERIFICATION_FAILED = "VERIFICATION_FAILED",
  SIGNING_FAILED = "SIGNING_FAILED",
  INVALID_SECRET = "INVALID_SECRET",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}

/**
 * JWT Result Type - Uses StandardResponse
 */
export type JwtResult<T> = StdResponse<T, JwtErrorType>

/**
 * JWT Error class - Production-grade error handling
 */
export class JwtError extends Error {
  public readonly type: JwtErrorType
  public readonly originalError?: Error
  public readonly timestamp: Date

  constructor(
    message: string,
    type: JwtErrorType = JwtErrorType.UNKNOWN_ERROR,
    originalError?: Error
  ) {
    super(message)
    this.name = "JwtError"
    this.type = type
    this.originalError = originalError
    this.timestamp = new Date()

    Object.setPrototypeOf(this, JwtError.prototype)
  }

  /**
   * Get error details as object
   */
  toJSON() {
    return {
      name: this.name,
      message: this.message,
      type: this.type,
      timestamp: this.timestamp.toISOString(),
      originalMessage: this.originalError?.message,
    }
  }
}

/**
 * JWT Payload - Base interface for decoded tokens
 */
export interface JwtPayload {
  [key: string]: unknown
  iat?: number
  exp?: number
  nbf?: number
  iss?: string
  sub?: string
  aud?: string | string[]
  jti?: string
}

/**
 * JWT Verify Options - Extends jsonwebtoken VerifyOptions
 */
export interface JwtVerifyOptions extends VerifyOptions {
  /**
   * Enable debug logging - will console.log errors for debugging
   */
  debug?: boolean
}

/**
 * JWT Sign Options - Extends jsonwebtoken SignOptions
 */
export type JwtSignOptions = SignOptions

/**
 * JWT Decode Options - Extends jsonwebtoken DecodeOptions
 */
export type JwtDecodeOptions = DecodeOptions

/**
 * Type guard to check if result is successful
 * @param result
 * @returns true if result is successful
 */
export function isSuccess<T>(result: JwtResult<T>): result is { status: "success"; result: T } {
  return result.status === "success"
}

/**
 * Type guard to check if result is an error
 * @param result
 * @returns true if result is an error
 */
export function isError<T>(result: JwtResult<T>): result is { status: "error"; error: { code: JwtErrorType; message?: string } } {
  return result.status === "error"
}
