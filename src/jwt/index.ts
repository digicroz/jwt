import jwt from "jsonwebtoken"
import type { JwtPayload } from "../types/jwt.types.js"
import {
  JwtResult,
  JwtError,
  JwtErrorType,
  type JwtVerifyOptions,
  type JwtSignOptions,
  type JwtDecodeOptions,
} from "../types/jwt.types.js"
import { stdResponse } from "@digicroz/js-kit/std-response"
import { isValidTokenStructure } from "../utils/timingSafe.js"

/**
 * Verify JWT token asynchronously with type safety
 * Returns JwtResult<Payload> - never throws
 *
 * @template T - Type of the decoded payload
 * @param token - JWT token to verify
 * @param secret - Secret key for verification
 * @param options - Verification options
 * @returns Promise<JwtResult<T>> - Either success with payload or error
 *
 * @example
 * const result = await jwtVerify<{userId: string}>(token, secret);
 * if (result.status === "success") {
 *   console.log(result.result.userId);
 * } else {
 *   console.error(result.error.message);
 * }
 */
export async function jwtVerify<T extends JwtPayload = JwtPayload>(
  token: string,
  secret: string | Buffer,
  options?: JwtVerifyOptions
): Promise<JwtResult<T>> {
  try {
    if (!token || typeof token !== "string") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "Invalid token: token must be a non-empty string"
      )
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return stdResponse.error(
        JwtErrorType.INVALID_SECRET,
        "Invalid secret: must be a string or Buffer"
      )
    }

    if (!isValidTokenStructure(token)) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "Invalid token structure: token is malformed"
      )
    }

    const payload = await new Promise<T>((resolve, reject) => {
      jwt.verify(
        token,
        secret,
        options || {},
        (err: Error | null, decoded: unknown) => {
          if (err) {
            reject(err)
          } else if (typeof decoded !== "object" || decoded === null) {
            reject(new jwt.JsonWebTokenError("Payload must be an object"))
          } else {
            resolve(decoded as T)
          }
        }
      )
    })

    return stdResponse.success(payload)
  } catch (error) {
    const jwtError = error as jwt.VerifyErrors | Error

    // Debug logging if enabled
    if (options?.debug) {
      console.log("[JWT Debug]", {
        errorName: (jwtError as any)?.name,
        errorMessage: (jwtError as any)?.message,
        fullError: jwtError,
      })
    }

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

    return stdResponse.error(errorType, message)
  }
}

/**
 * Sign JWT token asynchronously with type safety
 * Returns JwtResult<Token> - never throws
 *
 * @template T - Type of the payload
 * @param payload - Payload to sign
 * @param secret - Secret key for signing
 * @param options - Signing options
 * @returns Promise<JwtResult<string>> - Either success with token or error
 *
 * @example
 * const result = await jwtSign({userId: "123"}, secret, {expiresIn: "1h"});
 * if (result.status === "success") {
 *   console.log("Token:", result.result);
 * } else {
 *   console.error("Signing failed:", result.error.message);
 * }
 */
export async function jwtSign<T extends JwtPayload = JwtPayload>(
  payload: T,
  secret: string | Buffer,
  options?: JwtSignOptions
): Promise<JwtResult<string>> {
  try {
    if (!payload || typeof payload !== "object") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "Invalid payload: must be an object"
      )
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return stdResponse.error(
        JwtErrorType.INVALID_SECRET,
        "Invalid secret: must be a string or Buffer"
      )
    }

    const token = await new Promise<string>((resolve, reject) => {
      jwt.sign(
        payload,
        secret,
        options || {},
        (err: Error | null, encoded: string | undefined) => {
          if (err) {
            reject(err)
          } else if (!encoded) {
            reject(new Error("Token signing failed to produce a string"))
          } else {
            resolve(encoded)
          }
        }
      )
    })

    return stdResponse.success(token)
  } catch (error) {
    const jwtError = error as Error

    let errorType = JwtErrorType.SIGNING_FAILED
    const message = jwtError.message || "Token signing failed"

    return stdResponse.error(errorType, message)
  }
}

/**
 * Decode JWT token synchronously without verification
 * Useful for inspecting token contents without validation
 * Returns JwtResult<Payload> - never throws
 *
 * @template T - Type of the decoded payload
 * @param token - JWT token to decode
 * @param options - Decode options
 * @returns JwtResult<T> - Either success with payload or error
 *
 * @example
 * const result = jwtDecode<{userId: string}>(token);
 * if (result.status === "success") {
 *   console.log(result.result.userId);
 * }
 */
export function jwtDecode<T extends JwtPayload = JwtPayload>(
  token: string,
  options?: JwtDecodeOptions
): JwtResult<T> {
  try {
    if (!token || typeof token !== "string") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "Invalid token: must be a non-empty string"
      )
    }

    if (!isValidTokenStructure(token)) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "Invalid token structure: token is malformed"
      )
    }

    const decoded = jwt.decode(token, options || {})

    if (!decoded) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "Failed to decode token"
      )
    }

    if (typeof decoded !== "object") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "Payload must be an object"
      )
    }

    return stdResponse.success(decoded as T)
  } catch (error) {
    const jwtError = error as Error

    return stdResponse.error(
      JwtErrorType.MALFORMED_TOKEN,
      jwtError.message || "Failed to decode token"
    )
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
