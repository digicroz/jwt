import { describe, it, expect } from "vitest"
import {
  convertToSeconds,
  getUnixTimestampMs,
  getUnixTimestamp,
  getFullYear,
} from "./index"

describe("time utilities", () => {
  describe("convertToSeconds", () => {
    it("should convert seconds", () => {
      expect(convertToSeconds({ seconds: 30 })).toBe(30)
    })

    it("should convert minutes to seconds", () => {
      expect(convertToSeconds({ minutes: 2 })).toBe(120)
    })

    it("should convert hours to seconds", () => {
      expect(convertToSeconds({ hours: 1 })).toBe(3600)
    })

    it("should convert days to seconds", () => {
      expect(convertToSeconds({ days: 1 })).toBe(86400)
    })

    it("should convert months to seconds", () => {
      expect(convertToSeconds({ months: 1 })).toBe(2592000)
    })

    it("should convert years to seconds", () => {
      expect(convertToSeconds({ years: 1 })).toBe(31536000)
    })

    it("should combine multiple units", () => {
      expect(convertToSeconds({ hours: 1, minutes: 30, seconds: 45 })).toBe(
        5445
      )
    })

    it("should handle empty options", () => {
      expect(convertToSeconds()).toBe(0)
      expect(convertToSeconds({})).toBe(0)
    })

    it("should handle decimal values", () => {
      expect(convertToSeconds({ minutes: 1.5 })).toBe(90)
    })
  })

  describe("getUnixTimestampMs", () => {
    it("should return current timestamp when no argument", () => {
      const before = Date.now()
      const timestamp = getUnixTimestampMs()
      const after = Date.now()
      expect(timestamp).toBeGreaterThanOrEqual(before)
      expect(timestamp).toBeLessThanOrEqual(after)
    })

    it("should accept number timestamp", () => {
      const ts = 1609459200000 // 2021-01-01
      expect(getUnixTimestampMs(ts)).toBe(ts)
    })

    it("should accept Date object", () => {
      const date = new Date("2021-01-01")
      expect(getUnixTimestampMs(date)).toBe(date.getTime())
    })

    it("should accept date string", () => {
      const dateStr = "2021-01-01"
      const expected = new Date(dateStr).getTime()
      expect(getUnixTimestampMs(dateStr)).toBe(expected)
    })

    it("should throw error for invalid date string", () => {
      expect(() => getUnixTimestampMs("invalid")).toThrow(
        "Invalid date provided"
      )
    })

    it("should throw error for invalid number", () => {
      expect(() => getUnixTimestampMs(NaN)).toThrow(
        "Invalid timestamp provided"
      )
    })

    it("should throw error for negative timestamp", () => {
      expect(() => getUnixTimestampMs(-1000)).toThrow(
        "Timestamp is outside valid range"
      )
    })

    it("should throw error for timestamp too far in future", () => {
      const farFuture = Date.now() + 200 * 365 * 24 * 60 * 60 * 1000
      expect(() => getUnixTimestampMs(farFuture)).toThrow(
        "Timestamp is outside valid range"
      )
    })
  })

  describe("getUnixTimestamp", () => {
    it("should return timestamp in seconds", () => {
      const ms = Date.now()
      const seconds = Math.floor(ms / 1000)
      expect(getUnixTimestamp()).toBeCloseTo(seconds, -1)
    })

    it("should convert Date to seconds", () => {
      const date = new Date("2021-01-01")
      expect(getUnixTimestamp(date)).toBe(Math.floor(date.getTime() / 1000))
    })

    it("should handle string dates", () => {
      const dateStr = "2021-06-15"
      const expected = Math.floor(new Date(dateStr).getTime() / 1000)
      expect(getUnixTimestamp(dateStr)).toBe(expected)
    })

    it("should handle number timestamps", () => {
      const ms = 1609459200000
      expect(getUnixTimestamp(ms)).toBe(1609459200)
    })
  })

  describe("getFullYear", () => {
    it("should return current year when no argument", () => {
      const currentYear = new Date().getFullYear()
      expect(getFullYear()).toBe(currentYear)
    })

    it("should return year from provided date", () => {
      const date = new Date("2021-06-15")
      expect(getFullYear(date)).toBe(2021)
    })

    it("should handle different years", () => {
      expect(getFullYear(new Date("2025-01-01"))).toBe(2025)
      expect(getFullYear(new Date("1990-12-31"))).toBe(1990)
    })
  })
})
