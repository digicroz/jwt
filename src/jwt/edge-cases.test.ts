// import { describe, it, expect } from "vitest";
// import * as jwt from "jsonwebtoken";
// import { jwtDecode, jwtVerify } from "./index";
// import { JwtErrorType } from "../types/jwt.types";

// describe("JWT Edge Cases", () => {
//   it("should handle tokens with non-object payloads (string)", () => {
//     const secret = "test-secret";
//     const token = jwt.sign(JSON.stringify("string-payload"), secret);

//     const result = jwtDecode(token);

//     expect(result.status).toBe("error");
//     if (result.status === "error") {
//       expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       expect(result.error.message).toContain("Payload must be an object");
//     }
//   });

//   it("should handle tokens with non-object payloads (verify)", async () => {
//     const secret = "test-secret";
//     const token = jwt.sign(JSON.stringify("string-payload"), secret);

//     const result = await jwtVerify(token, secret);

//     expect(result.status).toBe("error");
//     if (result.status === "error") {
//       expect(result.error.code).toBe(JwtErrorType.INVALID_TOKEN);
//       expect(result.error.message).toContain("Payload must be an object");
//     }
//   });
// });
