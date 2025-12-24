import { describe, it, expect } from "vitest"
import { toSnakeCase, objectKeysToSnakeCase } from "./camelToSnake"

describe("string/caseConversion/camelToSnake", () => {
  describe("toSnakeCase", () => {
    it("should convert camelCase to snake_case", () => {
      expect(toSnakeCase("myVariable")).toBe("my_variable")
      expect(toSnakeCase("userName")).toBe("user_name")
    })

    it("should handle PascalCase", () => {
      expect(toSnakeCase("MyVariable")).toBe("my_variable")
      expect(toSnakeCase("UserName")).toBe("user_name")
    })

    it("should handle consecutive uppercase letters", () => {
      expect(toSnakeCase("XMLParser")).toBe("xml_parser")
      expect(toSnakeCase("HTTPRequest")).toBe("http_request")
    })

    it("should handle single word", () => {
      expect(toSnakeCase("hello")).toBe("hello")
      expect(toSnakeCase("HELLO")).toBe("hello")
    })

    it("should handle numbers", () => {
      expect(toSnakeCase("user2Name")).toBe("user2_name")
      expect(toSnakeCase("test123Value")).toBe("test123_value")
    })

    it("should handle already snake_case", () => {
      expect(toSnakeCase("already_snake_case")).toBe("already_snake_case")
    })

    it("should handle empty string", () => {
      expect(toSnakeCase("")).toBe("")
    })
  })

  describe("objectKeysToSnakeCase", () => {
    it("should convert object keys to snake_case", () => {
      const input = { firstName: "John", lastName: "Doe" }
      const result = objectKeysToSnakeCase(input)
      expect(result).toEqual({ first_name: "John", last_name: "Doe" })
    })

    it("should handle nested objects", () => {
      const input = { userInfo: { firstName: "John", phoneNumber: "123" } }
      const result = objectKeysToSnakeCase(input)
      expect(result).toEqual({
        user_info: { first_name: "John", phone_number: "123" },
      })
    })

    it("should handle arrays", () => {
      const input = { userList: [{ firstName: "John" }, { firstName: "Jane" }] }
      const result = objectKeysToSnakeCase(input)
      expect(result).toEqual({
        user_list: [{ first_name: "John" }, { first_name: "Jane" }],
      })
    })

    it("should handle primitive values", () => {
      expect(objectKeysToSnakeCase(null as any)).toBe(null)
      expect(objectKeysToSnakeCase("string" as any)).toBe("string")
      expect(objectKeysToSnakeCase(123 as any)).toBe(123)
    })

    it("should handle empty object", () => {
      expect(objectKeysToSnakeCase({})).toEqual({})
    })

    it("should handle deep nesting", () => {
      const input = {
        topLevel: {
          middleLevel: {
            deepLevel: { veryDeepKey: "value" },
          },
        },
      }
      const result = objectKeysToSnakeCase(input)
      expect(result).toEqual({
        top_level: {
          middle_level: {
            deep_level: { very_deep_key: "value" },
          },
        },
      })
    })

    it("should preserve values while converting keys", () => {
      const input = { userName: "JohnDoe", userAge: 30, isActive: true }
      const result = objectKeysToSnakeCase(input)
      expect(result).toEqual({
        user_name: "JohnDoe",
        user_age: 30,
        is_active: true,
      })
    })
  })
})
