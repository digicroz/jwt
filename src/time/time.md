# Time Utilities

Essential time conversion utilities for JavaScript/TypeScript applications with flexible time unit handling.

## Features

- âœ… **Full TypeScript Support** - Complete type definitions and type safety
- âœ… **Comprehensive JSDoc** - Detailed documentation for all functions
- âœ… **Flexible Time Units** - Support for seconds, minutes, hours, days, months, years
- âœ… **Mixed Unit Conversion** - Combine multiple time units in a single call
- âœ… **Error Handling** - Robust input validation and clear error messages
- âœ… **Performance Optimized** - Efficient time calculations
- âœ… **Zero Dependencies** - Pure JavaScript implementations

## Installation

```bash
npm install @digicroz/js-kit
```

## Usage

### Two Usage Patterns

You can use the time utilities in two ways:

#### 1. Individual Function Imports (Recommended)

```typescript
import {
  convertToSeconds,
  getUnixTimestamp,
  getUnixTimestampMs,
  getFullYear,
} from "@digicroz/js-kit/time"

const totalSeconds = convertToSeconds({ hours: 2, minutes: 30 }) // 9000 seconds
const currentTimestamp = getUnixTimestamp() // Current time in seconds
const currentTimestampMs = getUnixTimestampMs() // Current time in milliseconds
const currentYear = getFullYear() // Current year (e.g., 2025)
```

#### 2. Package Import

```typescript
import {
  convertToSeconds,
  getUnixTimestamp,
  getUnixTimestampMs,
  getFullYear,
} from "@digicroz/js-kit"

const totalSeconds = convertToSeconds({ hours: 2, minutes: 30 }) // 9000 seconds
```

### Basic Time Conversion

```typescript
import {
  convertToSeconds,
  getUnixTimestamp,
  getUnixTimestampMs,
  getFullYear,
} from "@digicroz/js-kit/time"

// Single unit conversions
const oneMinute = convertToSeconds({ minutes: 1 }) // 60 seconds
const oneHour = convertToSeconds({ hours: 1 }) // 3600 seconds
const oneDay = convertToSeconds({ days: 1 }) // 86400 seconds
const oneMonth = convertToSeconds({ months: 1 }) // 2592000 seconds (30 days)
const oneYear = convertToSeconds({ years: 1 }) // 31536000 seconds (365 days)

// No parameters - returns 0
const zero = convertToSeconds() // 0 seconds

// Get current timestamps
const currentTimestamp = getUnixTimestamp() // Current time in seconds
const currentTimestampMs = getUnixTimestampMs() // Current time in milliseconds

// Get current year
const currentYear = getFullYear() // Current year (e.g., 2025)
const specificYear = getFullYear(new Date("2023-05-15")) // 2023

// Use timestamps for comparisons and calculations
const timeInFuture = currentTimestamp + convertToSeconds({ hours: 1 }) // 1 hour from now
const timeAgo = currentTimestamp - convertToSeconds({ days: 7 }) // 1 week ago
```

### Mixed Unit Conversions

```typescript
import { convertToSeconds } from "@digicroz/js-kit/time"

// Combine multiple time units
const complexTime = convertToSeconds({
  years: 1,
  months: 6,
  days: 15,
  hours: 8,
  minutes: 30,
  seconds: 45,
})
// Result: 47,347,845 seconds (1 year, 6 months, 15 days, 8 hours, 30 minutes, 45 seconds)

// Common combinations
const workingDay = convertToSeconds({ hours: 8 }) // 28800 seconds (8-hour workday)
const workingWeek = convertToSeconds({ days: 5, hours: 8 }) // 172800 seconds (5 working days)
const semester = convertToSeconds({ months: 4 }) // 10368000 seconds (4-month semester)
```

### Practical Examples

```typescript
import { convertToSeconds } from "@digicroz/js-kit/time"

// Event planning
const conferenceLength = convertToSeconds({
  days: 3,
  hours: 8,
}) // 3-day conference, 8 hours per day

// Project timeline
const sprintDuration = convertToSeconds({
  days: 14,
}) // 2-week sprint

// Cache expiration
const cacheExpiry = convertToSeconds({
  hours: 24,
}) // 24-hour cache

// Session timeout
const sessionTimeout = convertToSeconds({
  minutes: 30,
}) // 30-minute session

// File retention
const logRetention = convertToSeconds({
  days: 90,
}) // 90-day log retention

// Subscription period
const monthlySubscription = convertToSeconds({
  months: 1,
}) // 1-month subscription

// Academic year
const academicYear = convertToSeconds({
  months: 10,
}) // 10-month academic year
```

### Integration with Date/Time APIs

```typescript
import { convertToSeconds } from "@digicroz/js-kit/time"

// Creating future dates
const futureTime = convertToSeconds({ days: 7, hours: 12 })
const futureDate = new Date(Date.now() + futureTime * 1000)

// Setting timeouts
const delaySeconds = convertToSeconds({ minutes: 5 })
setTimeout(() => {
  console.log("5 minutes have passed")
}, delaySeconds * 1000)

// Cache expiration with Redis/memory stores
const cacheExpirySeconds = convertToSeconds({ hours: 2 })
// Use cacheExpirySeconds with your caching solution

// Database timestamp calculations
const archiveAfter = convertToSeconds({ years: 1 })
const archiveTimestamp = Math.floor(Date.now() / 1000) + archiveAfter
```

### Working with APIs and Services

```typescript
import { convertToSeconds } from "@digicroz/js-kit/time"

// JWT token expiration
const tokenExpiry = convertToSeconds({ hours: 2 }) // 2-hour token
const jwtPayload = {
  userId: "123",
  exp: Math.floor(Date.now() / 1000) + tokenExpiry,
}

// Rate limiting
const rateLimitWindow = convertToSeconds({ minutes: 15 }) // 15-minute window
const maxRequests = 100

// Scheduled tasks
const dailyBackup = convertToSeconds({ days: 1 }) // Run every 24 hours
const weeklyReport = convertToSeconds({ days: 7 }) // Run every 7 days

// Health check intervals
const healthCheckInterval = convertToSeconds({ seconds: 30 }) // Every 30 seconds
```

## API Reference

### `convertToSeconds(options?)`

Converts various time units to total seconds.

#### Parameters

- `options` (object, optional): Configuration object with time units
  - `seconds?` (number): Number of seconds (default: 0)
  - `minutes?` (number): Number of minutes (default: 0)
  - `hours?` (number): Number of hours (default: 0)
  - `days?` (number): Number of days (default: 0)
  - `months?` (number): Number of months (default: 0, assumes 30 days per month)
  - `years?` (number): Number of years (default: 0, assumes 365 days per year)

#### Returns

- `number`: Total time converted to seconds

#### Examples

```typescript
// Basic usage
convertToSeconds({ minutes: 5 }) // 300
convertToSeconds({ hours: 2, minutes: 30 }) // 9000
convertToSeconds({ days: 1, hours: 12 }) // 129600

// Complex combinations
convertToSeconds({
  years: 1,
  months: 6,
  days: 15,
  hours: 8,
  minutes: 30,
  seconds: 45,
}) // 47347845

// Edge cases
convertToSeconds() // 0
convertToSeconds({}) // 0
```

## Time Conversion Reference

### Quick Reference Table

| Unit      | Seconds    | Minutes | Hours  | Days     |
| --------- | ---------- | ------- | ------ | -------- |
| 1 second  | 1          | 0.0167  | 0.0003 | 0.000012 |
| 1 minute  | 60         | 1       | 0.0167 | 0.0007   |
| 1 hour    | 3,600      | 60      | 1      | 0.0417   |
| 1 day     | 86,400     | 1,440   | 24     | 1        |
| 1 month\* | 2,592,000  | 43,200  | 720    | 30       |
| 1 year\*  | 31,536,000 | 525,600 | 8,760  | 365      |

\*Note: Months are calculated as 30 days, years as 365 days for consistency.

### Common Durations in Seconds

````typescript
// Common time periods
const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;
const WEEK = 604800;
const MONTH = 2592000;    // 30 days
const YEAR = 31536000;    // 365 days

// Using the utility
const minute = convertToSeconds({ minutes: 1 });     // 60
const hour = convertToSeconds({ hours: 1 });         // 3600
const day = convertToSeconds({ days: 1 });           // 86400
const week = convertToSeconds({ days: 7 });          // 604800
const month = convertToSeconds({ months: 1 });       // 2592000
const year = ### `getUnixTimestamp(): number`

Gets the current Unix timestamp in seconds.

**Returns:** `number` - Current Unix timestamp in seconds (integer)

**Examples:**
```typescript
const now = getUnixTimestamp();
// Returns: 1703000000 (example - current time in seconds)

// Use with other time functions
const oneHourFromNow = getUnixTimestamp() + convertToSeconds({ hours: 1 });
const oneDayAgo = getUnixTimestamp() - convertToSeconds({ days: 1 });
````

### `getUnixTimestampMs(): number`

Gets the current Unix timestamp in milliseconds.

**Returns:** `number` - Current Unix timestamp in milliseconds

**Examples:**

```typescript
const nowMs = getUnixTimestampMs()
// Returns: 1703000000000 (example - current time in milliseconds)

// Convert to seconds manually
const nowInSeconds = Math.floor(getUnixTimestampMs() / 1000)

// Use for high-precision timing
const startTime = getUnixTimestampMs()
// ... perform some operation
const endTime = getUnixTimestampMs()
const durationMs = endTime - startTime
```

## Best Practices

### 1. **Use Descriptive Variable Names**

```typescript
// âœ… Good
const sessionTimeoutSeconds = convertToSeconds({ minutes: 30 })
const cacheExpirationSeconds = convertToSeconds({ hours: 24 })

// âŒ Avoid
const timeout = convertToSeconds({ minutes: 30 })
const expiry = convertToSeconds({ hours: 24 })
```

### 2. **Combine Units for Clarity**

```typescript
// âœ… Good - Clear intent
const workingWeek = convertToSeconds({ days: 5, hours: 8 }) // 5 days Ã— 8 hours
const semester = convertToSeconds({ months: 4, days: 15 }) // 4.5 months

// âœ… Also good - Single unit if appropriate
const oneWeek = convertToSeconds({ days: 7 })
```

### 3. **Document Assumptions**

```typescript
// âœ… Good - Document assumptions in comments
const projectDuration = convertToSeconds({
  months: 6, // Assuming 30-day months for planning purposes
})

const fiscalYear = convertToSeconds({
  years: 1, // Standard 365-day year
})
```

### 4. **Consider Leap Years and Variable Month Lengths**

For precise calculations involving calendar dates, consider using date libraries like `date-fns` or `moment.js`. This utility is best for:

- Approximate calculations
- Configuration values
- Timeout/interval settings
- Performance measurements

## Performance

The `convertToSeconds` function is highly optimized:

- **O(1) time complexity** - Constant time execution
- **Minimal memory usage** - No arrays or complex objects created
- **Pure function** - No side effects, safe for concurrent use
- **Integer arithmetic** - Fast mathematical operations only

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
interface TimeOptions {
  seconds?: number
  minutes?: number
  hours?: number
  days?: number
  months?: number
  years?: number
}

function convertToSeconds(options?: TimeOptions): number
```

### `getUnixTimestamp(): number`

Gets the current Unix timestamp in seconds.

**Returns:** `number` - Current Unix timestamp in seconds (integer)

**Examples:**

```typescript
const now = getUnixTimestamp()
// Returns: 1703000000 (example - current time in seconds)

// Use with other time functions
const oneHourFromNow = getUnixTimestamp() + convertToSeconds({ hours: 1 })
const oneDayAgo = getUnixTimestamp() - convertToSeconds({ days: 1 })
```

### `getUnixTimestampMs(): number`

Gets the current Unix timestamp in milliseconds.

**Returns:** `number` - Current Unix timestamp in milliseconds

**Examples:**

```typescript
const nowMs = getUnixTimestampMs()
// Returns: 1703000000000 (example - current time in milliseconds)

// Convert to seconds manually
const nowInSeconds = Math.floor(getUnixTimestampMs() / 1000)

// Use for high-precision timing
const startTime = getUnixTimestampMs()
// ... perform some operation
const endTime = getUnixTimestampMs()
const durationMs = endTime - startTime
```

### `getFullYear(date?: Date): number`

Gets the full year from a Date object or the current date.

**Parameters:**

- `date` (Date, optional): Date object to extract year from. If not provided, uses current date.

**Returns:** `number` - The full year (4 digits)

**Examples:**

```typescript
// Get current year
const currentYear = getFullYear()
// Returns: 2025 (example - current year)

// Get year from specific date
const specificYear = getFullYear(new Date("2023-05-15"))
// Returns: 2023

// Use with date calculations
const birthYear = getFullYear(new Date("1990-03-20"))
const age = getFullYear() - birthYear

// Parse year from date string
const eventDate = new Date("December 31, 2024")
const eventYear = getFullYear(eventDate) // 2024
```

## Error Handling

The function includes robust input validation:

```typescript
// All these work safely
convertToSeconds() // Returns 0
convertToSeconds({}) // Returns 0
convertToSeconds({ minutes: undefined }) // Treats as 0
convertToSeconds({ hours: null }) // Treats as 0

// Type safety in TypeScript prevents invalid inputs
convertToSeconds({ minutes: "5" }) // TypeScript error
convertToSeconds({ invalid: 10 }) // TypeScript error
```

## Contributing

Found a bug or want to contribute? Check out our [contributing guidelines](../../CONTRIBUTING.md).

## License

MIT License - see [LICENSE](../../LICENSE) for details.
