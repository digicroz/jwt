// import { describe, it, expect, beforeEach } from "vitest";
// import { jwtVerify, jwtSign, jwtDecode } from "../jwt/index.js";
// import { JwtErrorType } from "../types/jwt.types.js";
// import { isValidTokenStructure } from "../utils/timingSafe.js";

// describe("JWT Package", () => {
//   const secret = "my-super-secret-key";
//   const payload = {
//     userId: "user-123",
//     email: "user@example.com",
//     role: "admin",
//   };

//   describe("jwtSign", () => {
//     it("should sign a token with basic payload", async () => {
//       const result = await jwtSign(payload, secret);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(typeof result.result).toBe("string");
//         expect(result.result.split(".").length).toBe(3);
//       }
//     });

//     it("should sign token with expiresIn option", async () => {
//       const result = await jwtSign(payload, secret, { expiresIn: "1h" });

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(typeof result.result).toBe("string");
//       }
//     });

//     it("should sign token with all common options", async () => {
//       const result = await jwtSign(payload, secret, {
//         expiresIn: "24h",
//         issuer: "my-app",
//         subject: "user-auth",
//         audience: "my-api",
//         algorithm: "HS256",
//       });

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(typeof result.result).toBe("string");
//       }
//     });

//     it("should handle invalid payload", async () => {
//       const result = await jwtSign(null as any, secret);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });

//     it("should handle invalid secret", async () => {
//       const result = await jwtSign(payload, null as any);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_SECRET);
//       }
//     });

//     it("should support Buffer as secret", async () => {
//       const bufferSecret = Buffer.from(secret);
//       const result = await jwtSign(payload, bufferSecret);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(typeof result.result).toBe("string");
//       }
//     });

//     it("should handle sign errors gracefully", async () => {
//       const result = await jwtSign(payload, secret, {
//         algorithm: "RS256" as any,
//       });
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.SIGNING_FAILED);
//       }
//     });
//   });

//   describe("jwtVerify", () => {
//     let validToken: string;

//     beforeEach(async () => {
//       const signResult = await jwtSign(payload, secret);
//       if (signResult.status === "success") {
//         validToken = signResult.result;
//       }
//     });

//     it("should verify a valid token", async () => {
//       const result = await jwtVerify(validToken, secret);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(result.result.userId).toBe(payload.userId);
//         expect(result.result.email).toBe(payload.email);
//         expect(result.result.role).toBe(payload.role);
//       }
//     });

//     it("should verify with generic type parameter", async () => {
//       interface CustomPayload extends Record<string, unknown> {
//         userId: string;
//         email: string;
//         role: string;
//       }

//       const result = await jwtVerify<CustomPayload>(validToken, secret);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         const typedData: CustomPayload = result.result;
//         expect(typedData.userId).toBe(payload.userId);
//       }
//     });

//     it("should reject token with wrong secret", async () => {
//       const result = await jwtVerify(validToken, "wrong-secret");

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });

//     it("should handle expired tokens", async () => {
//       const expiredSignResult = await jwtSign(payload, secret, {
//         expiresIn: "-1h",
//       });

//       if (expiredSignResult.status === "success") {
//         const result = await jwtVerify(expiredSignResult.result, secret);

//         expect(result.status).toBe("error");
//         if (result.status === "error") {
//           expect(result.error.code).toBe(JwtErrorType.EXPIRED_TOKEN);
//         }
//       }
//     });

//     it("should ignore expiration when requested", async () => {
//       const expiredSignResult = await jwtSign(payload, secret, {
//         expiresIn: "-1h",
//       });

//       if (expiredSignResult.status === "success") {
//         const result = await jwtVerify(expiredSignResult.result, secret, {
//           ignoreExpiration: true,
//         });
//         expect(result.status).toBe("success");
//       }
//     });

//     it("should handle malformed tokens", async () => {
//       const result = await jwtVerify("not.a.valid.token.string", secret);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.MALFORMED_TOKEN);
//       }
//     });

//     it("should handle empty token", async () => {
//       const result = await jwtVerify("", secret);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });

//     it("should handle null token", async () => {
//       const result = await jwtVerify(null as any, secret);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });

//     it("should handle invalid secret", async () => {
//       const result = await jwtVerify(validToken, null as any);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_SECRET);
//       }
//     });

//     it("should support Buffer as secret", async () => {
//       const bufferSecret = Buffer.from(secret);
//       const result = await jwtVerify(validToken, bufferSecret);
//       expect(result.status).toBe("success");
//     });

//     it("should verify with custom options", async () => {
//       const tokenWithIssuer = await jwtSign(payload, secret, {
//         issuer: "test-issuer",
//       });

//       if (tokenWithIssuer.status === "success") {
//         const result = await jwtVerify(tokenWithIssuer.result, secret, {
//           issuer: "test-issuer",
//         });
//         expect(result.status).toBe("success");
//       }
//     });

//     it("should reject token with wrong issuer", async () => {
//       const tokenWithIssuer = await jwtSign(payload, secret, {
//         issuer: "test-issuer",
//       });

//       if (tokenWithIssuer.status === "success") {
//         const result = await jwtVerify(tokenWithIssuer.result, secret, {
//           issuer: "wrong-issuer",
//         });
//         expect(result.status).toBe("error");
//       }
//     });

//     it("should handle different JWT error types correctly", async () => {
//       const expiredToken = await jwtSign(payload, secret, { expiresIn: "-1s" });
//       if (expiredToken.status === "error") return;

//       const result = await jwtVerify(expiredToken.result, secret);
//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.EXPIRED_TOKEN);
//         expect(result.error.message).toBeTruthy();
//       }
//     });
//   });

//   describe("jwtDecode", () => {
//     let validToken: string;

//     beforeEach(async () => {
//       const signResult = await jwtSign(payload, secret);
//       if (signResult.status === "success") {
//         validToken = signResult.result;
//       }
//     });

//     it("should decode a token without verification", () => {
//       const result = jwtDecode(validToken);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         expect(result.result.userId).toBe(payload.userId);
//         expect(result.result.email).toBe(payload.email);
//       }
//     });

//     it("should decode token with generic type", () => {
//       interface CustomPayload extends Record<string, unknown> {
//         userId: string;
//         email: string;
//         role: string;
//       }

//       const result = jwtDecode<CustomPayload>(validToken);

//       expect(result.status).toBe("success");
//       if (result.status === "success") {
//         const typedData: CustomPayload = result.result;
//         expect(typedData.role).toBe(payload.role);
//       }
//     });

//     it("should handle malformed tokens", () => {
//       const result = jwtDecode("not.a.valid.token");

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.MALFORMED_TOKEN);
//       }
//     });

//     it("should handle empty token", () => {
//       const result = jwtDecode("");

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });

//     it("should handle null token", () => {
//       const result = jwtDecode(null as any);

//       expect(result.status).toBe("error");
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       }
//     });
//   });

//   describe("Token Structure Validation", () => {
//     let validToken: string;

//     beforeEach(async () => {
//       const signResult = await jwtSign(payload, secret);
//       if (signResult.status === "success") {
//         validToken = signResult.result;
//       }
//     });

//     it("should validate correct token structure", () => {
//       expect(isValidTokenStructure(validToken)).toBe(true);
//     });

//     it("should reject malformed tokens", () => {
//       expect(isValidTokenStructure("invalid")).toBe(false);
//       expect(isValidTokenStructure("a.b.c.d")).toBe(false);
//       expect(isValidTokenStructure("a.b")).toBe(false);
//     });

//     it("should reject non-string input", () => {
//       expect(isValidTokenStructure(null as any)).toBe(false);
//       expect(isValidTokenStructure(undefined as any)).toBe(false);
//     });
//   });

//   describe("Integration", () => {
//     it("should sign, verify, and decode in sequence", async () => {
//       const signResult = await jwtSign(payload, secret, { expiresIn: "1h" });
//       expect(signResult.status).toBe("success");
//       if (signResult.status === "error") return;

//       const token = signResult.result;

//       const verifyResult = await jwtVerify(token, secret);
//       expect(verifyResult.status).toBe("success");
//       if (verifyResult.status === "error") return;
//       expect(verifyResult.result.userId).toBe(payload.userId);

//       const decodeResult = jwtDecode(token);
//       expect(decodeResult.status).toBe("success");
//       if (decodeResult.status === "error") return;
//       expect(decodeResult.result.userId).toBe(payload.userId);
//     });

//     it("should handle multiple tokens independently", async () => {
//       const payload1 = { userId: "user1", role: "admin" };
//       const payload2 = { userId: "user2", role: "user" };

//       const token1 = await jwtSign(payload1, secret);
//       const token2 = await jwtSign(payload2, secret);

//       expect(token1.status).toBe("success");
//       expect(token2.status).toBe("success");
//       if (token1.status === "error" || token2.status === "error") return;

//       const verify1 = await jwtVerify(token1.result, secret);
//       const verify2 = await jwtVerify(token2.result, secret);

//       expect(verify1.status).toBe("success");
//       expect(verify2.status).toBe("success");
//       if (verify1.status === "error" || verify2.status === "error") return;

//       expect(verify1.result.userId).toBe("user1");
//       expect(verify2.result.userId).toBe("user2");
//     });

//     it("should handle rapid sequential operations", async () => {
//       const operations = [];

//       for (let i = 0; i < 10; i++) {
//         const p = { userId: `user${i}` };
//         const signPromise = jwtSign(p, secret).then((signResult) => {
//           if (signResult.status === "success") {
//             return jwtVerify(signResult.result, secret).then((r) => r);
//           }
//           return signResult as any;
//         });
//         operations.push(signPromise);
//       }

//       const results = await Promise.all(operations);
//       expect(results.every((r) => r.status === "success")).toBe(true);
//     });
//   });

//   describe("Type Narrowing", () => {
//     it("should narrow success result", async () => {
//       const result = await jwtSign(payload, secret);

//       if (result.status === "success") {
//         const token = result.result;
//         expect(typeof token).toBe("string");
//         expect(token.split(".").length).toBe(3);
//       }
//     });

//     it("should narrow error result", async () => {
//       const result = await jwtSign(null as any, secret);

//       if (result.status === "error") {
//         const error = result.error;
//         expect(error.message).toBeTruthy();
//         expect(error.code).toBeTruthy();
//       }
//     });

//     it("should narrow async verify result", async () => {
//       const token = await jwtSign(payload, secret);
//       if (token.status === "success") {
//         const result = await jwtVerify(token.result, secret);
//         if (result.status === "success") {
//           expect(result.result.userId).toBe(payload.userId);
//           expect(result.result.email).toBe(payload.email);
//         }
//       }
//     });

//     it("should narrow async error result", async () => {
//       const result = await jwtVerify("invalid.token.here", secret);
//       if (result.status === "error") {
//         expect(result.error.code).toBe(JwtErrorType.MALFORMED_TOKEN);
//       }
//     });
//   });
// });
