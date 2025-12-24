import { describe, it, expect } from "vitest"
import {
  clamp,
  inRange,
  convertToInt,
  convertToTwoDecimalInt,
  randomNumberWithFixedLength,
} from "./index"

describe("number utilities", () => {
  describe("clamp", () => {
    it("should clamp number to lower bound", () => {
      expect(clamp(5, 10, 20)).toBe(10)
    })

    it("should clamp number to upper bound", () => {
      expect(clamp(25, 10, 20)).toBe(20)
    })

    it("should return number if within bounds", () => {
      expect(clamp(15, 10, 20)).toBe(15)
    })

    it("should handle equal bounds", () => {
      expect(clamp(5, 10, 10)).toBe(10)
      expect(clamp(10, 10, 10)).toBe(10)
    })

    it("should throw error for invalid inputs", () => {
      expect(() => clamp("5" as any, 10, 20)).toThrow(
        "All arguments must be numbers"
      )
      expect(() => clamp(5, "10" as any, 20)).toThrow(
        "All arguments must be numbers"
      )
    })

    it("should throw error when lower > upper", () => {
      expect(() => clamp(15, 20, 10)).toThrow(
        "Lower bound must be less than or equal to upper bound"
      )
    })

    it("should handle negative numbers", () => {
      expect(clamp(-5, -10, -1)).toBe(-5)
      expect(clamp(-15, -10, -1)).toBe(-10)
    })
  })

  describe("inRange", () => {
    it("should return true for number within range", () => {
      expect(inRange(15, 10, 20)).toBe(true)
    })

    it("should return true for number at lower bound", () => {
      expect(inRange(10, 10, 20)).toBe(true)
    })

    it("should return true for number at upper bound", () => {
      expect(inRange(20, 10, 20)).toBe(true)
    })

    it("should return false for number below range", () => {
      expect(inRange(5, 10, 20)).toBe(false)
    })

    it("should return false for number above range", () => {
      expect(inRange(25, 10, 20)).toBe(false)
    })

    it("should throw error for invalid inputs", () => {
      expect(() => inRange("15" as any, 10, 20)).toThrow(
        "All arguments must be numbers"
      )
    })

    it("should throw error when lower > upper", () => {
      expect(() => inRange(15, 20, 10)).toThrow(
        "Lower bound must be less than or equal to upper bound"
      )
    })
  })

  describe("convertToInt", () => {
    it("should convert string number to int", () => {
      expect(convertToInt("123")).toBe(123)
    })

    it("should convert number to int", () => {
      expect(convertToInt(123)).toBe(123)
    })

    it("should handle decimal numbers", () => {
      expect(convertToInt("123.45")).toBe(123)
      expect(convertToInt(123.45)).toBe(123)
    })

    it("should throw error for null", () => {
      expect(() => convertToInt(null)).toThrow(
        "Invalid input: null or undefined"
      )
    })

    it("should throw error for undefined", () => {
      expect(() => convertToInt(undefined)).toThrow(
        "Invalid input: not a number"
      )
    })

    it("should throw error for non-numeric string", () => {
      expect(() => convertToInt("abc")).toThrow("Invalid input: not a number")
    })
  })

  describe("convertToTwoDecimalInt", () => {
    it("should convert to two decimal places", () => {
      expect(convertToTwoDecimalInt("123.456")).toBe(123.46)
      expect(convertToTwoDecimalInt(123.456)).toBe(123.46)
    })

    it("should handle numbers with less than two decimals", () => {
      expect(convertToTwoDecimalInt("123.4")).toBe(123.4)
      expect(convertToTwoDecimalInt(123)).toBe(123.0)
    })

    it("should throw error for null", () => {
      expect(() => convertToTwoDecimalInt(null)).toThrow(
        "Invalid input: null or undefined"
      )
    })

    it("should throw error for undefined", () => {
      expect(() => convertToTwoDecimalInt(undefined)).toThrow(
        "Invalid input: not a number"
      )
    })

    it("should throw error for non-numeric string", () => {
      expect(() => convertToTwoDecimalInt("abc")).toThrow(
        "Invalid input: not a number"
      )
    })
  })

  describe("randomNumberWithFixedLength", () => {
    it("should generate number with specified length", () => {
      const num = randomNumberWithFixedLength(5)
      expect(num.toString().length).toBe(5)
      expect(num).toBeGreaterThanOrEqual(10000)
      expect(num).toBeLessThan(100000)
    })

    it("should generate single digit", () => {
      const num = randomNumberWithFixedLength(1)
      expect(num).toBeGreaterThanOrEqual(1)
      expect(num).toBeLessThan(10)
    })

    it("should throw error for zero length", () => {
      expect(() => randomNumberWithFixedLength(0)).toThrow(
        "Length must be a positive integer."
      )
    })

    it("should throw error for negative length", () => {
      expect(() => randomNumberWithFixedLength(-1)).toThrow(
        "Length must be a positive integer."
      )
    })

    it("should throw error for non-integer length", () => {
      expect(() => randomNumberWithFixedLength(3.5)).toThrow(
        "Length must be a positive integer."
      )
    })
  })
})
