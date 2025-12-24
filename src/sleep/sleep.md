# Sleep Utilities

Advanced sleep and timing utilities for JavaScript/TypeScript applications with flexible delay options.

## Features

- âœ… **Full TypeScript Support** - Complete type definitions and interfaces
- âœ… **Comprehensive JSDoc** - Detailed documentation for all functions
- âœ… **Flexible Timing** - Multiple delay formats (ms, seconds, minutes)
- âœ… **Random Delays** - Support for random delay ranges
- âœ… **Timestamp Scheduling** - Sleep until specific Unix timestamps
- âœ… **Error Handling** - Robust input validation and error messages
- âœ… **Modern Promise API** - Async/await support throughout
- âœ… **Zero Dependencies** - Pure JavaScript implementations

## Installation

```bash
npm install @digicroz/js-kit
```

## Usage

### Two Usage Patterns

You can use the sleep utilities in two ways:

#### 1. Individual Function Imports (Recommended)

```typescript
import {
  sleep,
  sleepMs,
  sleepSeconds,
  sleepUntil,
} from "@digicroz/js-kit/sleep"

await sleepMs(1000) // Sleep for 1 second
await sleepSeconds(2) // Sleep for 2 seconds
await sleep({ minutes: 1, seconds: 30 }) // Sleep for 1.5 minutes
```

#### 2. Package Import

```typescript
import { sleep, sleepMs, sleepSeconds, sleepUntil } from "@digicroz/js-kit"

await sleepMs(1000)
```

### Basic Sleep Operations

```typescript
import {
  sleep,
  sleepMs,
  sleepSeconds,
  sleepMinutes,
} from "@digicroz/js-kit/sleep"

// Simple delays
await sleepMs(500) // Sleep for 500 milliseconds
await sleepSeconds(2) // Sleep for 2 seconds
await sleepMinutes(1) // Sleep for 1 minute

// Combined delays
await sleep({
  minutes: 1,
  seconds: 30,
  milliseconds: 500,
}) // Sleep for 1 minute, 30.5 seconds total

// Sleep for exactly 5.5 seconds
await sleep({ seconds: 5, milliseconds: 500 })
```

### Random Delays

```typescript
import { sleep } from "@digicroz/js-kit/sleep"

// Random delay between 1-3 seconds
await sleep({
  random: {
    seconds: { min: 1, max: 3 },
  },
})

// Random delay between 100-500 milliseconds
await sleep({
  random: {
    milliseconds: { min: 100, max: 500 },
  },
})

// Random delay between 1-5 minutes
await sleep({
  random: {
    minutes: { min: 1, max: 5 },
  },
})
```

### Timestamp-Based Sleeping

```typescript
import { sleep, sleepUntil } from "@digicroz/js-kit/sleep"

// Sleep until a specific Unix timestamp (in seconds)
const targetTime = Math.floor(Date.now() / 1000) + 60 // 1 minute from now
await sleepUntil(targetTime)

// Using the sleep function with timestamp
await sleep({
  until: {
    unixTimestamp: targetTime,
  },
})

// Sleep until tomorrow at midnight
const tomorrow = new Date()
tomorrow.setDate(tomorrow.getDate() + 1)
tomorrow.setHours(0, 0, 0, 0)
const tomorrowTimestamp = Math.floor(tomorrow.getTime() / 1000)

await sleepUntil(tomorrowTimestamp)
```

### Advanced Usage Examples

```typescript
import { sleep, sleepMs } from "@digicroz/js-kit/sleep"

// Rate limiting with jitter
const rateLimitedApiCall = async (url: string) => {
  try {
    const response = await fetch(url)

    // Add random jitter to prevent thundering herd
    await sleep({
      random: {
        milliseconds: { min: 100, max: 300 },
      },
    })

    return response
  } catch (error) {
    // Exponential backoff with random jitter
    const backoffMs = Math.min(1000 * Math.pow(2, retryCount), 30000)
    await sleep({
      random: {
        milliseconds: { min: backoffMs * 0.5, max: backoffMs * 1.5 },
      },
    })
    throw error
  }
}

// Polling with progressive delays
const pollForCondition = async <T>(
  checkCondition: () => Promise<T | null>,
  maxAttempts: number = 10
): Promise<T> => {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const result = await checkCondition()
    if (result !== null) {
      return result
    }

    if (attempt < maxAttempts) {
      // Progressive delay: 1s, 2s, 4s, 8s, etc.
      const delaySeconds = Math.min(Math.pow(2, attempt - 1), 30)
      console.log(`Attempt ${attempt} failed, retrying in ${delaySeconds}s...`)
      await sleepSeconds(delaySeconds)
    }
  }

  throw new Error(`Condition not met after ${maxAttempts} attempts`)
}

// Scheduled task execution
const scheduleTask = async (
  taskFn: () => Promise<void>,
  scheduleTime: Date
) => {
  const now = Date.now()
  const targetTime = scheduleTime.getTime()

  if (targetTime <= now) {
    console.log("Executing task immediately (scheduled time has passed)")
    await taskFn()
    return
  }

  const delayMs = targetTime - now
  console.log(`Task scheduled for ${scheduleTime.toISOString()}`)
  console.log(`Waiting ${Math.round(delayMs / 1000)}s until execution...`)

  await sleepMs(delayMs)
  console.log("Executing scheduled task...")
  await taskFn()
}

// Example usage
const futureTime = new Date(Date.now() + 5000) // 5 seconds from now
await scheduleTask(async () => {
  console.log("Task executed!")
}, futureTime)
```

### Retry Mechanisms

```typescript
import { sleep } from "@digicroz/js-kit/sleep"

// Simple retry with fixed delay
const retryWithFixedDelay = async <T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  delayMs: number = 1000
): Promise<T> => {
  let lastError: Error

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await operation()
    } catch (error) {
      lastError = error as Error

      if (attempt <= maxRetries) {
        console.log(`Attempt ${attempt} failed, retrying in ${delayMs}ms...`)
        await sleepMs(delayMs)
      }
    }
  }

  throw lastError!
}

// Exponential backoff with jitter
const retryWithBackoff = async <T>(
  operation: () => Promise<T>,
  maxRetries: number = 5,
  baseDelayMs: number = 1000,
  maxDelayMs: number = 30000
): Promise<T> => {
  let lastError: Error

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await operation()
    } catch (error) {
      lastError = error as Error

      if (attempt <= maxRetries) {
        // Exponential backoff: baseDelay * 2^(attempt-1)
        const baseDelay = Math.min(
          baseDelayMs * Math.pow(2, attempt - 1),
          maxDelayMs
        )

        // Add jitter (Â±25% of base delay)
        await sleep({
          random: {
            milliseconds: {
              min: baseDelay * 0.75,
              max: baseDelay * 1.25,
            },
          },
        })
      }
    }
  }

  throw lastError!
}

// Linear backoff
const retryWithLinearBackoff = async <T>(
  operation: () => Promise<T>,
  maxRetries: number = 3,
  initialDelayMs: number = 1000,
  incrementMs: number = 500
): Promise<T> => {
  let lastError: Error

  for (let attempt = 1; attempt <= maxRetries + 1; attempt++) {
    try {
      return await operation()
    } catch (error) {
      lastError = error as Error

      if (attempt <= maxRetries) {
        const delayMs = initialDelayMs + (attempt - 1) * incrementMs
        console.log(`Attempt ${attempt} failed, retrying in ${delayMs}ms...`)
        await sleepMs(delayMs)
      }
    }
  }

  throw lastError!
}

// Example usage
const unreliableApiCall = async (): Promise<string> => {
  if (Math.random() < 0.7) {
    throw new Error("API temporarily unavailable")
  }
  return "Success!"
}

try {
  const result = await retryWithBackoff(unreliableApiCall, 3)
  console.log(result)
} catch (error) {
  console.error("All retry attempts failed:", error.message)
}
```

### Background Task Management

```typescript
import { sleep, sleepMs } from "@digicroz/js-kit/sleep"

// Background worker with sleep intervals
class BackgroundWorker {
  private running = false
  private intervalMs: number

  constructor(private workFn: () => Promise<void>, intervalMs: number = 5000) {
    this.intervalMs = intervalMs
  }

  async start(): Promise<void> {
    if (this.running) return

    this.running = true
    console.log("Background worker started")

    while (this.running) {
      try {
        await this.workFn()
      } catch (error) {
        console.error("Background worker error:", error)
      }

      // Sleep with random jitter to prevent synchronized workers
      await sleep({
        random: {
          milliseconds: {
            min: this.intervalMs * 0.8,
            max: this.intervalMs * 1.2,
          },
        },
      })
    }

    console.log("Background worker stopped")
  }

  stop(): void {
    this.running = false
  }
}

// Heartbeat mechanism
class HeartbeatService {
  private intervalMs: number
  private running = false

  constructor(
    private sendHeartbeat: () => Promise<void>,
    intervalMs: number = 30000
  ) {
    this.intervalMs = intervalMs
  }

  async start(): Promise<void> {
    this.running = true

    while (this.running) {
      try {
        await this.sendHeartbeat()
        console.log("Heartbeat sent successfully")
      } catch (error) {
        console.error("Heartbeat failed:", error)
      }

      await sleepMs(this.intervalMs)
    }
  }

  stop(): void {
    this.running = false
  }
}

// Usage examples
const worker = new BackgroundWorker(async () => {
  console.log("Performing background task...")
  // Simulate work
  await sleepMs(1000)
}, 10000)

// Start worker (runs in background)
worker.start()

// Stop after 1 minute
setTimeout(() => {
  worker.stop()
}, 60000)
```

### Testing and Development Utilities

```typescript
import { sleep, sleepMs } from "@digicroz/js-kit/sleep"

// Simulate slow operations for testing
const simulateSlowApi = async (
  responseTime: number = 2000
): Promise<string> => {
  console.log(`Simulating API call (${responseTime}ms)...`)
  await sleepMs(responseTime)
  return "API Response"
}

// Progressive loading simulation
const simulateProgressiveLoading = async (steps: string[]): Promise<void> => {
  for (let i = 0; i < steps.length; i++) {
    console.log(`Step ${i + 1}/${steps.length}: ${steps[i]}`)

    // Random delay between 500ms and 1.5s for each step
    await sleep({
      random: {
        milliseconds: { min: 500, max: 1500 },
      },
    })
  }

  console.log("Loading complete!")
}

// Throttled function execution
const throttle = <T extends (...args: any[]) => Promise<any>>(
  fn: T,
  delayMs: number
): ((...args: Parameters<T>) => Promise<ReturnType<T>>) => {
  let lastExecution = 0

  return async (...args: Parameters<T>): Promise<ReturnType<T>> => {
    const now = Date.now()
    const timeSinceLastExecution = now - lastExecution

    if (timeSinceLastExecution < delayMs) {
      await sleepMs(delayMs - timeSinceLastExecution)
    }

    lastExecution = Date.now()
    return await fn(...args)
  }
}

// Example usage
const throttledApiCall = throttle(async (data: string) => {
  console.log("API call with:", data)
  return `Response for ${data}`
}, 1000)

// These calls will be throttled to 1 call per second
await throttledApiCall("data1")
await throttledApiCall("data2")
await throttledApiCall("data3")
```

### Error Handling

```typescript
import { sleep, sleepMs } from "@digicroz/js-kit/sleep"

try {
  // Invalid parameters will throw errors
  await sleep({}) // Error: Sleep parameters cannot be empty
} catch (error) {
  console.error(error.message)
}

try {
  await sleep({ milliseconds: -100 }) // Error: Milliseconds cannot be negative
} catch (error) {
  console.error(error.message)
}

try {
  await sleep({
    random: {
      seconds: { min: 5, max: 2 }, // Error: Invalid range
    },
  })
} catch (error) {
  console.error(error.message)
}

// Safe sleep with validation
const safeSleep = async (params: any): Promise<boolean> => {
  try {
    await sleep(params)
    return true
  } catch (error) {
    console.error("Sleep failed:", error.message)
    return false
  }
}

// Timeout wrapper for sleep operations
const sleepWithTimeout = async (
  sleepParams: Parameters<typeof sleep>[0],
  timeoutMs: number
): Promise<void> => {
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => reject(new Error("Sleep timeout exceeded")), timeoutMs)
  })

  await Promise.race([sleep(sleepParams), timeoutPromise])
}

// Usage
try {
  await sleepWithTimeout({ minutes: 10 }, 5000) // Will timeout after 5s
} catch (error) {
  console.error(error.message) // "Sleep timeout exceeded"
}
```

## API Reference

### `sleep(params: TSleepParams): Promise<void>`

Advanced sleep function with flexible delay options.

**Parameters:**

- `params` - Sleep configuration object

**TSleepParams Interface:**

```typescript
type TSleepParams = {
  milliseconds?: number
  seconds?: number
  minutes?: number
  until?: {
    unixTimestamp?: number
  }
  random?: {
    milliseconds?: { min: number; max: number }
    seconds?: { min: number; max: number }
    minutes?: { min: number; max: number }
  }
}
```

**Returns:** `Promise<void>` - Resolves after the specified delay

**Throws:** `Error` when parameters are invalid

### `sleepMs(ms: number): Promise<void>`

Sleep for a specific number of milliseconds.

**Parameters:**

- `ms` - Number of milliseconds to sleep

**Returns:** `Promise<void>`

### `sleepSeconds(seconds: number): Promise<void>`

Sleep for a specific number of seconds.

**Parameters:**

- `seconds` - Number of seconds to sleep

**Returns:** `Promise<void>`

### `sleepMinutes(minutes: number): Promise<void>`

Sleep for a specific number of minutes.

**Parameters:**

- `minutes` - Number of minutes to sleep

**Returns:** `Promise<void>`

### `sleepUntil(unixTimestamp: number): Promise<void>`

Sleep until a specific Unix timestamp (in seconds).

**Parameters:**

- `unixTimestamp` - Unix timestamp in seconds

**Returns:** `Promise<void>` - Resolves at the specified time

## Type Definitions

```typescript
type TSleepParams = {
  milliseconds?: number
  seconds?: number
  minutes?: number
  until?: {
    unixTimestamp?: number
  }
  random?: {
    milliseconds?: { min: number; max: number }
    seconds?: { min: number; max: number }
    minutes?: { min: number; max: number }
  }
}

type TSleepReturn = Promise<void>
```

## Best Practices

1. **Use appropriate delay types**: Choose the most readable format (ms, seconds, minutes)
2. **Add jitter to prevent thundering herd**: Use random delays for distributed systems
3. **Implement exponential backoff**: For retry mechanisms, use increasing delays
4. **Validate inputs**: Always validate delay parameters in production code
5. **Consider memory usage**: Long sleeps don't consume CPU but maintain promise references
6. **Use for rate limiting**: Implement delays between API calls to respect rate limits
7. **Handle edge cases**: Consider timezone changes when using timestamp-based sleeping

## Common Use Cases

### API Rate Limiting

```typescript
import { sleep } from "@digicroz/js-kit/sleep"

class RateLimitedApiClient {
  private lastCallTime = 0
  private minInterval = 1000 // 1 second between calls

  async makeRequest(url: string): Promise<Response> {
    const now = Date.now()
    const timeSinceLastCall = now - this.lastCallTime

    if (timeSinceLastCall < this.minInterval) {
      await sleepMs(this.minInterval - timeSinceLastCall)
    }

    this.lastCallTime = Date.now()
    return fetch(url)
  }
}
```

### Batch Processing

```typescript
import { sleep } from "@digicroz/js-kit/sleep"

const processBatch = async <T>(
  items: T[],
  processor: (item: T) => Promise<void>,
  batchSize: number = 10,
  delayBetweenBatches: number = 1000
): Promise<void> => {
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize)

    await Promise.all(batch.map(processor))

    if (i + batchSize < items.length) {
      console.log(
        `Processed batch ${Math.floor(i / batchSize) + 1}, sleeping...`
      )
      await sleepMs(delayBetweenBatches)
    }
  }
}
```

### Scheduled Tasks

```typescript
import { sleepUntil } from "@digicroz/js-kit/sleep"

const runDailyTask = async (taskFn: () => Promise<void>): Promise<void> => {
  while (true) {
    // Calculate next midnight
    const tomorrow = new Date()
    tomorrow.setDate(tomorrow.getDate() + 1)
    tomorrow.setHours(0, 0, 0, 0)

    const tomorrowTimestamp = Math.floor(tomorrow.getTime() / 1000)

    console.log(`Next execution scheduled for ${tomorrow.toISOString()}`)
    await sleepUntil(tomorrowTimestamp)

    try {
      await taskFn()
    } catch (error) {
      console.error("Daily task failed:", error)
    }
  }
}
```

## Performance Considerations

- **Memory Usage**: Sleep operations maintain promise references but don't consume CPU
- **Timer Precision**: JavaScript timers have ~4ms minimum resolution in browsers
- **Maximum Delay**: Limited to 2,147,483,647ms (~24.8 days) due to setTimeout limits
- **No Busy Waiting**: All functions use native setTimeout for efficient waiting

## License

This module is part of the @digicroz/js-kit package.
