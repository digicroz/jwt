/**
 * JWT Result Pattern - Represents success or failure without throwing
 */

import type { VerifyOptions, SignOptions, DecodeOptions } from "jsonwebtoken"

/**
 * Success result
 */
export interface SuccessResult<T> {
  readonly success: true
  readonly data: T
}

/**
 * Error result
 */
export interface ErrorResult {
  readonly success: false
  readonly error: JwtError
}

/**
 * Union type for Result - Either Success or Error
 */
export type Result<T> = SuccessResult<T> | ErrorResult

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
export function isSuccess<T>(result: Result<T>): result is SuccessResult<T> {
  return result.success === true
}

/**
 * Type guard to check if result is an error
 * @param result
 * @returns true if result is an error
 */
export function isError<T>(result: Result<T>): result is ErrorResult {
  return result.success === false
}

/**
 * Helper function to check negation
 * @deprecated Use isError instead
 */
export function hasError<T>(result: Result<T>): result is ErrorResult {
  return result.success === false
}
