import { describe, it, expect } from "vitest"
import { toCamelCase, objectKeysToCamelCase } from "./snakeToCamel"

describe("string/caseConversion/snakeToCamel", () => {
  describe("toCamelCase", () => {
    it("should convert snake_case to camelCase", () => {
      expect(toCamelCase("my_variable")).toBe("myVariable")
      expect(toCamelCase("user_name")).toBe("userName")
    })

    it("should handle single word", () => {
      expect(toCamelCase("hello")).toBe("hello")
    })

    it("should handle multiple underscores", () => {
      expect(toCamelCase("user_first_name")).toBe("userFirstName")
      expect(toCamelCase("is_active_user")).toBe("isActiveUser")
    })

    it("should handle already camelCase", () => {
      expect(toCamelCase("alreadyCamelCase")).toBe("alreadyCamelCase")
    })

    it("should handle empty string", () => {
      expect(toCamelCase("")).toBe("")
    })

    it("should handle numbers", () => {
      expect(toCamelCase("user_2_name")).toBe("user_2Name")
    })

    it("should handle consecutive underscores", () => {
      expect(toCamelCase("hello__world")).toBe("hello_World")
    })
  })

  describe("objectKeysToCamelCase", () => {
    it("should convert object keys to camelCase", () => {
      const input = { first_name: "John", last_name: "Doe" }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({ firstName: "John", lastName: "Doe" })
    })

    it("should handle nested objects", () => {
      const input = { user_info: { first_name: "John", phone_number: "123" } }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({
        userInfo: { firstName: "John", phoneNumber: "123" },
      })
    })

    it("should handle arrays", () => {
      const input = {
        user_list: [{ first_name: "John" }, { first_name: "Jane" }],
      }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({
        userList: [{ firstName: "John" }, { firstName: "Jane" }],
      })
    })

    it("should handle primitive values", () => {
      expect(objectKeysToCamelCase(null as any)).toBe(null)
      expect(objectKeysToCamelCase("string" as any)).toBe("string")
      expect(objectKeysToCamelCase(123 as any)).toBe(123)
    })

    it("should handle empty object", () => {
      expect(objectKeysToCamelCase({})).toEqual({})
    })

    it("should handle deep nesting", () => {
      const input = {
        top_level: {
          middle_level: {
            deep_level: { very_deep_key: "value" },
          },
        },
      }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({
        topLevel: {
          middleLevel: {
            deepLevel: { veryDeepKey: "value" },
          },
        },
      })
    })

    it("should preserve values while converting keys", () => {
      const input = { user_name: "john_doe", user_age: 30, is_active: true }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({
        userName: "john_doe",
        userAge: 30,
        isActive: true,
      })
    })

    it("should handle mixed case keys", () => {
      const input = { user_name: "John", UserAge: 30 }
      const result = objectKeysToCamelCase(input)
      expect(result).toEqual({ userName: "John", UserAge: 30 })
    })
  })
})
