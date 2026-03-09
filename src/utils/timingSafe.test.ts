import { describe, it, expect } from "vitest";
import { isValidTokenStructure } from "../utils/timingSafe.ts";

describe("Token Structure Validation", () => {
  describe("isValidTokenStructure", () => {
    it("should validate proper JWT token structure", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
      expect(isValidTokenStructure(jwt)).toBe(true);
    });

    it("should reject malformed token", () => {
      expect(isValidTokenStructure("not.valid.token")).toBe(false);
    });

    it("should reject token with only 2 parts", () => {
      expect(isValidTokenStructure("header.payload")).toBe(false);
    });

    it("should reject token with 4 parts", () => {
      expect(isValidTokenStructure("a.b.c.d")).toBe(false);
    });

    it("should reject non-string input", () => {
      expect(isValidTokenStructure(null as any)).toBe(false);
      expect(isValidTokenStructure(undefined as any)).toBe(false);
      expect(isValidTokenStructure(123 as any)).toBe(false);
    });

    it("should reject token with non-JSON payload", () => {
      expect(isValidTokenStructure("header.notjson.signature")).toBe(false);
    });

    it("should handle tokens with complex JSON payloads", () => {
      const jsonPayload = JSON.stringify({ sub: "user", role: "admin" });
      const encoded = Buffer.from(jsonPayload).toString("base64");
      const token = `header.${encoded}.signature`;
      expect(isValidTokenStructure(token)).toBe(true);
    });
  });
});
