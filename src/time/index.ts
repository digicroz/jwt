/**
 * Converts various time units to total seconds
 * @param options - Object containing optional time units
 * @param options.seconds - Number of seconds (default: 0)
 * @param options.minutes - Number of minutes (default: 0)
 * @param options.hours - Number of hours (default: 0)
 * @param options.days - Number of days (default: 0)
 * @param options.months - Number of months (default: 0, assumes 30 days per month)
 * @param options.years - Number of years (default: 0, assumes 365 days per year)
 * @returns Total time in seconds
 */
export function convertToSeconds(
  options: {
    seconds?: number
    minutes?: number
    hours?: number
    days?: number
    months?: number
    years?: number
  } = {}
): number {
  const {
    seconds = 0,
    minutes = 0,
    hours = 0,
    days = 0,
    months = 0,
    years = 0,
  } = options

  // Time conversion constants
  const SECONDS_PER_MINUTE = 60
  const SECONDS_PER_HOUR = 60 * 60
  const SECONDS_PER_DAY = 60 * 60 * 24
  const SECONDS_PER_MONTH = 60 * 60 * 24 * 30 // Assuming 30 days per month
  const SECONDS_PER_YEAR = 60 * 60 * 24 * 365 // Assuming 365 days per year

  return (
    seconds +
    minutes * SECONDS_PER_MINUTE +
    hours * SECONDS_PER_HOUR +
    days * SECONDS_PER_DAY +
    months * SECONDS_PER_MONTH +
    years * SECONDS_PER_YEAR
  )
}

/**
 * Gets Unix timestamp in milliseconds
 * @param date - Optional Date object, date string, or timestamp. If not provided, uses current date
 * @returns Unix timestamp in milliseconds
 */
export const getUnixTimestampMs = (date?: Date | string | number): number => {
  if (date === undefined) {
    return Date.now()
  }

  if (typeof date === "number") {
    const testDate = new Date(date)
    if (isNaN(testDate.getTime())) {
      throw new Error("Invalid timestamp provided")
    }

    // Timestamps should be positive and not too far in the future
    const now = Date.now()
    const hundredYearsFromNow = now + 100 * 365 * 24 * 60 * 60 * 1000 // 100 years

    if (date < 0 || date > hundredYearsFromNow) {
      throw new Error("Timestamp is outside valid range")
    }

    return date
  }

  const dateObj = new Date(date)

  if (isNaN(dateObj.getTime())) {
    throw new Error("Invalid date provided")
  }

  return dateObj.getTime()
}

/**
 * Gets Unix timestamp in seconds
 * @param date - Optional Date object, date string, or timestamp. If not provided, uses current date
 * @returns Unix timestamp in seconds
 */
export const getUnixTimestamp = (date?: Date | string | number): number => {
  return Math.floor(getUnixTimestampMs(date) / 1000)
}

/**
 * Gets the full year from a Date object or the current date
 * @param date - Optional Date object. If not provided, uses current date
 * @returns The full year (4 digits)
 */
export const getFullYear = (date?: Date): number => {
  const targetDate = date || new Date()
  return targetDate.getFullYear()
}
