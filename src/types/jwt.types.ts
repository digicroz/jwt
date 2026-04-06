import type { VerifyOptions, SignOptions, DecodeOptions } from "jsonwebtoken"
import type { StdResponse } from "@digicroz/js-kit/std-response"

export enum JwtErrorType {
  INVALID_TOKEN = "invalid_token",
  EXPIRED_TOKEN = "expired_token",
  MALFORMED_TOKEN = "malformed_token",
  VERIFICATION_FAILED = "verify_failed",
  SIGNING_FAILED = "sign_failed",
  INVALID_SECRET = "invalid_secret",
}

export type JwtResult<T> = StdResponse<T, JwtErrorType>

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

export interface JwtVerifyOptions extends VerifyOptions {
  debug?: boolean
}

export type JwtSignOptions = SignOptions

export type JwtDecodeOptions = DecodeOptions
