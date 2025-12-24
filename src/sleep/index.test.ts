import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { sleep, sleepMs, sleepSeconds, sleepMinutes, sleepUntil } from "./index"

describe("sleep utilities", () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  describe("sleep", () => {
    it("should sleep for specified milliseconds", async () => {
      const promise = sleep({ milliseconds: 100 })
      vi.advanceTimersByTime(100)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should sleep for specified seconds", async () => {
      const promise = sleep({ seconds: 2 })
      vi.advanceTimersByTime(2000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should sleep for specified minutes", async () => {
      const promise = sleep({ minutes: 1 })
      vi.advanceTimersByTime(60000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should combine multiple time units", async () => {
      const promise = sleep({ seconds: 1, milliseconds: 500 })
      vi.advanceTimersByTime(1500)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should throw error for empty parameters", async () => {
      await expect(sleep({})).rejects.toThrow(
        "Sleep parameters cannot be empty"
      )
    })

    it("should throw error for negative milliseconds", async () => {
      await expect(sleep({ milliseconds: -100 })).rejects.toThrow(
        "Milliseconds cannot be negative"
      )
    })

    it("should throw error for negative seconds", async () => {
      await expect(sleep({ seconds: -1 })).rejects.toThrow(
        "Seconds cannot be negative"
      )
    })

    it("should throw error for negative minutes", async () => {
      await expect(sleep({ minutes: -1 })).rejects.toThrow(
        "Minutes cannot be negative"
      )
    })

    it("should throw error when no delay parameter specified", async () => {
      await expect(
        sleep({ milliseconds: 0, seconds: 0, minutes: 0 })
      ).rejects.toThrow("At least one delay parameter must be specified")
    })

    it("should throw error for delay too large", async () => {
      await expect(sleep({ milliseconds: 2147483648 })).rejects.toThrow(
        "Delay too large"
      )
    })
  })

  describe("sleepUntil", () => {
    it("should sleep until specific timestamp", async () => {
      const futureTimestamp = Math.floor(Date.now() / 1000) + 5
      const promise = sleepUntil(futureTimestamp)
      vi.advanceTimersByTime(5000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should resolve immediately for past timestamps", async () => {
      const pastTimestamp = Math.floor(Date.now() / 1000) - 10
      const promise = sleepUntil(pastTimestamp)
      await expect(promise).resolves.toBeUndefined()
    })
  })

  describe("random sleep", () => {
    it("should sleep for random milliseconds in range", async () => {
      const promise = sleep({
        random: { milliseconds: { min: 100, max: 200 } },
      })
      vi.advanceTimersByTime(200)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should sleep for random seconds in range", async () => {
      const promise = sleep({ random: { seconds: { min: 1, max: 2 } } })
      vi.advanceTimersByTime(2000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should sleep for random minutes in range", async () => {
      const promise = sleep({ random: { minutes: { min: 1, max: 2 } } })
      vi.advanceTimersByTime(120000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("should throw error for invalid random milliseconds range", async () => {
      await expect(
        sleep({ random: { milliseconds: { min: -1, max: 100 } } })
      ).rejects.toThrow("Invalid random milliseconds range")
    })

    it("should throw error for invalid random seconds range", async () => {
      await expect(
        sleep({ random: { seconds: { min: 5, max: 2 } } })
      ).rejects.toThrow("Invalid random seconds range")
    })

    it("should throw error for invalid random minutes range", async () => {
      await expect(
        sleep({ random: { minutes: { min: 10, max: 5 } } })
      ).rejects.toThrow("Invalid random minutes range")
    })

    it("should throw error when random type not specified", async () => {
      await expect(sleep({ random: {} })).rejects.toThrow(
        "Random delay type must be specified"
      )
    })
  })

  describe("convenience functions", () => {
    it("sleepMs should work", async () => {
      const promise = sleepMs(100)
      vi.advanceTimersByTime(100)
      await expect(promise).resolves.toBeUndefined()
    })

    it("sleepSeconds should work", async () => {
      const promise = sleepSeconds(2)
      vi.advanceTimersByTime(2000)
      await expect(promise).resolves.toBeUndefined()
    })

    it("sleepMinutes should work", async () => {
      const promise = sleepMinutes(1)
      vi.advanceTimersByTime(60000)
      await expect(promise).resolves.toBeUndefined()
    })
  })
})
