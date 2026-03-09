import jwt from "jsonwebtoken";
import type { JwtPayload } from "../types/jwt.types.js";
import {
  JwtErrorType,
  type JwtResult,
  type JwtVerifyOptions,
  type JwtSignOptions,
  type JwtDecodeOptions,
} from "../types/jwt.types.js";
import { stdResponse } from "@digicroz/js-kit/std-response";
import { isValidTokenStructure } from "../utils/timingSafe.js";

type TJwtVerifyProps = {
  token: string;
  secret: string | Buffer;
  options?: JwtVerifyOptions;
};

export async function jwtVerify<T extends JwtPayload = JwtPayload>({
  token,
  secret,
  options,
}: TJwtVerifyProps): Promise<JwtResult<T>> {
  try {
    if (!token || typeof token !== "string") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "token must be a non-empty string",
      );
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return stdResponse.error(
        JwtErrorType.INVALID_SECRET,
        "secret must be a string or Buffer",
      );
    }

    if (!isValidTokenStructure(token)) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "token is malformed",
      );
    }

    const payload = await new Promise<T>((resolve, reject) => {
      jwt.verify(
        token,
        secret,
        options || {},
        (err: Error | null, decoded: unknown) => {
          if (err) {
            reject(err);
          } else if (typeof decoded !== "object" || decoded === null) {
            reject(new jwt.JsonWebTokenError("Payload must be an object"));
          } else {
            resolve(decoded as T);
          }
        },
      );
    });

    return stdResponse.success(payload);
  } catch (error) {
    const jwtError = error as jwt.VerifyErrors | Error;

    if (options?.debug) {
      console.log("[JWT Debug]", {
        errorName: (jwtError as any)?.name,
        errorMessage: (jwtError as any)?.message,
        fullError: jwtError,
      });
    }

    let errorType = JwtErrorType.VERIFICATION_FAILED;
    let message = "token verification failed";

    if ("name" in jwtError) {
      switch (jwtError.name) {
        case "TokenExpiredError":
          errorType = JwtErrorType.EXPIRED_TOKEN;
          message = `token expired at ${(jwtError as jwt.TokenExpiredError).expiredAt?.toISOString()}`;
          break;
        case "JsonWebTokenError":
          errorType = JwtErrorType.INVALID_TOKEN;
          message = jwtError.message || "invalid token";
          break;
        case "NotBeforeError":
          errorType = JwtErrorType.INVALID_TOKEN;
          message = "token not yet valid";
          break;
        case "SyntaxError":
          errorType = JwtErrorType.MALFORMED_TOKEN;
          message = "malformed token";
          break;
      }
    }

    return stdResponse.error(errorType, message);
  }
}

type TJwtSignProps = {
  payload: JwtPayload;
  secret: string | Buffer;
  options?: JwtSignOptions;
};

export async function jwtSign<T extends JwtPayload = JwtPayload>({
  payload,
  secret,
  options,
}: TJwtSignProps): Promise<JwtResult<string>> {
  try {
    if (!payload || typeof payload !== "object") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "payload must be an object",
      );
    }

    if (!secret || (typeof secret !== "string" && !Buffer.isBuffer(secret))) {
      return stdResponse.error(
        JwtErrorType.INVALID_SECRET,
        "secret must be a string or Buffer",
      );
    }

    const token = await new Promise<string>((resolve, reject) => {
      jwt.sign(
        payload,
        secret,
        options || {},
        (err: Error | null, encoded: string | undefined) => {
          if (err) {
            reject(err);
          } else if (!encoded) {
            reject(new Error("token signing produced no output"));
          } else {
            resolve(encoded);
          }
        },
      );
    });

    return stdResponse.success(token);
  } catch (error) {
    const jwtError = error as Error;
    return stdResponse.error(
      JwtErrorType.SIGNING_FAILED,
      jwtError.message || "token signing failed",
    );
  }
}

type TJwtDecodeProps = {
  token: string;
  options?: JwtDecodeOptions;
};

export function jwtDecode<T extends JwtPayload = JwtPayload>({
  token,
  options,
}: TJwtDecodeProps): JwtResult<T> {
  try {
    if (!token || typeof token !== "string") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "token must be a non-empty string",
      );
    }

    if (!isValidTokenStructure(token)) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "token is malformed",
      );
    }

    const decoded = jwt.decode(token, options || {});

    if (!decoded) {
      return stdResponse.error(
        JwtErrorType.MALFORMED_TOKEN,
        "failed to decode token",
      );
    }

    if (typeof decoded !== "object") {
      return stdResponse.error(
        JwtErrorType.INVALID_TOKEN,
        "Payload must be an object",
      );
    }

    return stdResponse.success(decoded as T);
  } catch (error) {
    const jwtError = error as Error;
    return stdResponse.error(
      JwtErrorType.MALFORMED_TOKEN,
      jwtError.message || "failed to decode token",
    );
  }
}
