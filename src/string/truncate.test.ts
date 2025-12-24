import { describe, it, expect } from "vitest"
import { truncateText } from "./truncate"

describe("string/truncate", () => {
  describe("truncateText", () => {
    it("should truncate text longer than maxLength", () => {
      expect(truncateText({ text: "Hello World", maxLength: 5 })).toBe(
        "Hello..."
      )
    })

    it("should not truncate text shorter than maxLength", () => {
      expect(truncateText({ text: "Hello", maxLength: 10 })).toBe("Hello")
    })

    it("should use default maxLength of 10", () => {
      expect(truncateText({ text: "This is a long text" })).toBe(
        "This is a ..."
      )
    })

    it("should use custom suffix", () => {
      expect(
        truncateText({ text: "Hello World", maxLength: 5, suffix: "---" })
      ).toBe("Hello---")
    })

    it("should handle empty suffix", () => {
      expect(
        truncateText({ text: "Hello World", maxLength: 5, suffix: "" })
      ).toBe("Hello")
    })

    it("should handle text exactly at maxLength", () => {
      expect(truncateText({ text: "Hello", maxLength: 5 })).toBe("Hello")
    })

    it("should handle empty text", () => {
      expect(truncateText({ text: "", maxLength: 5 })).toBe("")
    })

    it("should handle maxLength of 0", () => {
      expect(truncateText({ text: "Hello", maxLength: 0 })).toBe("...")
    })

    it("should handle unicode characters", () => {
      expect(truncateText({ text: "Hello 世界", maxLength: 5 })).toBe(
        "Hello..."
      )
    })

    it("should handle emojis", () => {
      expect(truncateText({ text: "Hello 🌍🌎🌏", maxLength: 6 })).toBe(
        "Hello ..."
      )
    })
  })
})
