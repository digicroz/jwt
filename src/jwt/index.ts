import * as jwt from "jsonwebtoken"
import type { JwtPayload } from "../types/jwt.types.js"
import {
  Result,
  JwtError,
  JwtErrorType,
  type JwtVerifyOptions,
  type JwtSignOptions,
  type JwtDecodeOptions,
} from "../types/jwt.types.js"
import { isValidTokenStructure } from "../utils/timingSafe.js"

/**
 * Verify JWT token asynchronously with type safety
 * Returns Result<Payload> - never throws
 *
 * @template T - Type of the decoded payload
 * @param token - JWT token to verify
 * @param secret - Secret key for verification
 * @param options - Verification options
 * @returns Promise<Result<T>> - Either success with payload or error
 *
 * @example
 * const result = await jwtVerify<{userId: string}>(token, secret);
 * if (result.success) {
 *   console.log(result.data.userId);
 * } else {
 *   console.error(result.error.message);
 * }
 */
export async function jwtVerify<T extends JwtPayload = JwtPayload>(
  token: string,
  secret: string | Buffer,
  options?: JwtVerifyOptions
): Promise<Result<T>> {
  try {
    if (!token || typeof token !== "string") {
      return {
        success: false as const,
        error: new JwtError(
          "Invalid token: token must be a non-empty string",
          JwtErrorType.INVALID_TOKEN
        ),
      }
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return {
        success: false,
        error: new JwtError(
          "Invalid secret: must be a string or Buffer",
          JwtErrorType.INVALID_SECRET
        ),
      }
    }

    if (!isValidTokenStructure(token)) {
      return {
        success: false,
        error: new JwtError(
          "Invalid token structure: token is malformed",
          JwtErrorType.MALFORMED_TOKEN
        ),
      }
    }

    const payload = await new Promise<T>((resolve, reject) => {
      jwt.verify(
        token,
        secret,
        options || {},
        (err: Error | null, decoded: unknown) => {
          if (err) {
            reject(err)
          } else {
            resolve(decoded as T)
          }
        }
      )
    })

    return {
      success: true as const,
      data: payload,
    }
  } catch (error) {
    const jwtError = error as jwt.VerifyErrors | Error

    let errorType = JwtErrorType.VERIFICATION_FAILED
    let message = "Token verification failed"

    if ("name" in jwtError) {
      switch (jwtError.name) {
        case "TokenExpiredError":
          errorType = JwtErrorType.EXPIRED_TOKEN
          message = `Token expired at ${(
            jwtError as jwt.TokenExpiredError
          ).expiredAt?.toISOString()}`
          break
        case "JsonWebTokenError":
          errorType = JwtErrorType.INVALID_TOKEN
          message = jwtError.message || "Invalid token"
          break
        case "NotBeforeError":
          errorType = JwtErrorType.INVALID_TOKEN
          message = "Token not yet valid"
          break
        case "SyntaxError":
          errorType = JwtErrorType.MALFORMED_TOKEN
          message = "Malformed token"
          break
      }
    }

    return {
      success: false as const,
      error: new JwtError(message, errorType, jwtError as Error),
    }
  }
}

/**
 * Sign JWT token synchronously with type safety
 * Returns Result<Token> - never throws
 *
 * @template T - Type of the payload
 * @param payload - Payload to sign
 * @param secret - Secret key for signing
 * @param options - Signing options
 * @returns Result<string> - Either success with token or error
 *
 * @example
 * const result = jwtSign({userId: "123"}, secret, {expiresIn: "1h"});
 * if (result.success) {
 *   console.log("Token:", result.data);
 * } else {
 *   console.error("Signing failed:", result.error.message);
 * }
 */
export function jwtSign<T extends JwtPayload = JwtPayload>(
  payload: T,
  secret: string | Buffer,
  options?: JwtSignOptions
): Result<string> {
  try {
    if (!payload || typeof payload !== "object") {
      return {
        success: false as const,
        error: new JwtError(
          "Invalid payload: must be an object",
          JwtErrorType.INVALID_TOKEN
        ),
      }
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return {
        success: false as const,
        error: new JwtError(
          "Invalid secret: must be a string or Buffer",
          JwtErrorType.INVALID_SECRET
        ),
      }
    }

    const token = jwt.sign(payload, secret, options || {})

    return {
      success: true as const,
      data: token,
    }
  } catch (error) {
    const jwtError = error as Error

    let errorType = JwtErrorType.SIGNING_FAILED
    const message = jwtError.message || "Token signing failed"

    return {
      success: false as const,
      error: new JwtError(message, errorType, jwtError),
    }
  }
}

/**
 * Decode JWT token synchronously without verification
 * Useful for inspecting token contents without validation
 * Returns Result<Payload> - never throws
 *
 * @template T - Type of the decoded payload
 * @param token - JWT token to decode
 * @param options - Decode options
 * @returns Result<T> - Either success with payload or error
 *
 * @example
 * const result = jwtDecode<{userId: string}>(token);
 * if (result.success) {
 *   console.log(result.data.userId);
 * }
 */
export function jwtDecode<T extends JwtPayload = JwtPayload>(
  token: string,
  options?: JwtDecodeOptions
): Result<T> {
  try {
    if (!token || typeof token !== "string") {
      return {
        success: false as const,
        error: new JwtError(
          "Invalid token: must be a non-empty string",
          JwtErrorType.INVALID_TOKEN
        ),
      }
    }

    if (!isValidTokenStructure(token)) {
      return {
        success: false as const,
        error: new JwtError(
          "Invalid token structure: token is malformed",
          JwtErrorType.MALFORMED_TOKEN
        ),
      }
    }

    const decoded = jwt.decode(token, options || {})

    if (!decoded) {
      return {
        success: false as const,
        error: new JwtError(
          "Failed to decode token",
          JwtErrorType.MALFORMED_TOKEN
        ),
      }
    }

    return {
      success: true as const,
      data: decoded as T,
    }
  } catch (error) {
    const jwtError = error as Error

    return {
      success: false as const,
      error: new JwtError(
        jwtError.message || "Failed to decode token",
        JwtErrorType.MALFORMED_TOKEN,
        jwtError
      ),
    }
  }
}

/**
 * @deprecated Use jwtVerify instead
 */
export const jwtVerifyAsync = (jwtToken: string, secret: string | Buffer) => {
  return new Promise<unknown>((resolve, reject) => {
    jwt.verify(jwtToken, secret, function (err, payload) {
      if (err) {
        reject(err)
      }
      resolve(payload)
    })
  })
}
