import { describe, it, expect } from "vitest"
import { parseEnumValue, requireEnumValue } from "./index"

describe("enum utilities", () => {
  const Colors = ["red", "green", "blue"] as const
  const Status = ["active", "inactive", "pending"] as const

  describe("parseEnumValue", () => {
    it("should return enum value when valid", () => {
      expect(parseEnumValue(Colors, "red")).toBe("red")
      expect(parseEnumValue(Colors, "green")).toBe("green")
      expect(parseEnumValue(Colors, "blue")).toBe("blue")
    })

    it("should return undefined for invalid value", () => {
      expect(parseEnumValue(Colors, "yellow")).toBeUndefined()
      expect(parseEnumValue(Colors, "purple")).toBeUndefined()
      expect(parseEnumValue(Colors, "")).toBeUndefined()
    })

    it("should be case sensitive", () => {
      expect(parseEnumValue(Colors, "Red")).toBeUndefined()
      expect(parseEnumValue(Colors, "RED")).toBeUndefined()
    })

    it("should work with different enum arrays", () => {
      expect(parseEnumValue(Status, "active")).toBe("active")
      expect(parseEnumValue(Status, "inactive")).toBe("inactive")
      expect(parseEnumValue(Status, "pending")).toBe("pending")
    })

    it("should handle empty strings", () => {
      expect(parseEnumValue(Colors, "")).toBeUndefined()
    })

    it("should handle special characters", () => {
      const Special = ["hello-world", "test_case"] as const
      expect(parseEnumValue(Special, "hello-world")).toBe("hello-world")
      expect(parseEnumValue(Special, "test_case")).toBe("test_case")
    })
  })

  describe("requireEnumValue", () => {
    it("should return enum value when valid", () => {
      expect(requireEnumValue(Colors, "red")).toBe("red")
      expect(requireEnumValue(Colors, "green")).toBe("green")
      expect(requireEnumValue(Colors, "blue")).toBe("blue")
    })

    it("should throw error for invalid value", () => {
      expect(() => requireEnumValue(Colors, "yellow")).toThrow(
        "Invalid enum value: yellow"
      )
      expect(() => requireEnumValue(Colors, "purple")).toThrow(
        "Invalid enum value: purple"
      )
    })

    it("should throw error with correct message", () => {
      expect(() => requireEnumValue(Status, "deleted")).toThrow(
        "Invalid enum value: deleted"
      )
    })

    it("should be case sensitive", () => {
      expect(() => requireEnumValue(Colors, "Red")).toThrow(
        "Invalid enum value: Red"
      )
      expect(() => requireEnumValue(Colors, "RED")).toThrow(
        "Invalid enum value: RED"
      )
    })

    it("should throw error for empty string", () => {
      expect(() => requireEnumValue(Colors, "")).toThrow("Invalid enum value: ")
    })

    it("should work with different enum arrays", () => {
      expect(requireEnumValue(Status, "active")).toBe("active")
      expect(requireEnumValue(Status, "inactive")).toBe("inactive")
      expect(requireEnumValue(Status, "pending")).toBe("pending")
    })

    it("should handle numbers as strings", () => {
      const Numbers = ["1", "2", "3"] as const
      expect(requireEnumValue(Numbers, "1")).toBe("1")
      expect(() => requireEnumValue(Numbers, "4")).toThrow(
        "Invalid enum value: 4"
      )
    })
  })
})
