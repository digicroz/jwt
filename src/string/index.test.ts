import { describe, it, expect } from "vitest"
import { randomStringWithFixedLength } from "./index"

describe("randomStringWithFixedLength", () => {
  it("should generate string of specified length", () => {
    const result = randomStringWithFixedLength(10)
    expect(result).toHaveLength(10)
  })

  it("should generate different strings on multiple calls", () => {
    const str1 = randomStringWithFixedLength(20)
    const str2 = randomStringWithFixedLength(20)
    expect(str1).not.toBe(str2)
  })

  it("should generate string with length 1", () => {
    const result = randomStringWithFixedLength(1)
    expect(result).toHaveLength(1)
  })

  it("should generate longer strings correctly", () => {
    const result = randomStringWithFixedLength(100)
    expect(result).toHaveLength(100)
  })

  it("should only contain alphanumeric characters", () => {
    const result = randomStringWithFixedLength(50)
    expect(result).toMatch(/^[a-z0-9]+$/)
  })

  it("should throw error for non-integer length", () => {
    expect(() => randomStringWithFixedLength(5.5)).toThrow(
      "Length must be a positive integer."
    )
  })

  it("should throw error for zero length", () => {
    expect(() => randomStringWithFixedLength(0)).toThrow(
      "Length must be a positive integer."
    )
  })

  it("should throw error for negative length", () => {
    expect(() => randomStringWithFixedLength(-5)).toThrow(
      "Length must be a positive integer."
    )
  })
})
