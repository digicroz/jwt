# Number Utilities

Essential number manipulation utilities for JavaScript/TypeScript applications.

## Features

- âœ… **Full TypeScript Support** - Complete type definitions and type safety
- âœ… **Comprehensive JSDoc** - Detailed documentation for all functions
- âœ… **Error Handling** - Robust input validation and clear error messages
- âœ… **Mathematical Precision** - Accurate number operations and bounds checking
- âœ… **Performance Optimized** - Efficient implementations using native Math functions
- âœ… **Zero Dependencies** - Pure JavaScript implementations

## Installation

```bash
npm install @digicroz/js-kit
```

## Usage

### Two Usage Patterns

You can use the number utilities in two ways:

#### 1. Individual Function Imports (Recommended)

```typescript
import {
  clamp,
  inRange,
  convertToInt,
  convertToTwoDecimalInt,
  randomNumberWithFixedLength,
} from "@digicroz/js-kit/number"

const clampedValue = clamp(15, 0, 10) // Result: 10
const isInRange = inRange(5, 0, 10) // Result: true
const intValue = convertToInt("123.45") // Result: 123
const decimalValue = convertToTwoDecimalInt("123.456789") // Result: 123.46
const randomNum = randomNumberWithFixedLength(4) // Result: 5847 (example)
```

#### 2. Package Import

```typescript
import {
  clamp,
  inRange,
  convertToInt,
  convertToTwoDecimalInt,
  randomNumberWithFixedLength,
} from "@digicroz/js-kit"

const clampedValue = clamp(15, 0, 10) // Result: 10
```

### Basic Number Operations

```typescript
import {
  clamp,
  inRange,
  convertToInt,
  convertToTwoDecimalInt,
  randomNumberWithFixedLength,
} from "@digicroz/js-kit/number"

// Clamp values within bounds
const temperature = clamp(105, 0, 100) // Result: 100
const volume = clamp(-5, 0, 100) // Result: 0
const brightness = clamp(50, 0, 100) // Result: 50

// Check if values are within range
const isValidPercentage = inRange(85, 0, 100) // Result: true
const isValidTemperature = inRange(-10, 0, 100) // Result: false
const isValidScore = inRange(75, 0, 100) // Result: true

// Convert to integers safely
const userAge = convertToInt("25") // Result: 25
const scoreFromString = convertToInt("87.9") // Result: 87
const fromNumber = convertToInt(123.456) // Result: 123

// Convert to two decimal places
const price = convertToTwoDecimalInt("19.999") // Result: 20.00
const percentage = convertToTwoDecimalInt(85.6789) // Result: 85.68
const precise = convertToTwoDecimalInt("123.1") // Result: 123.10

// Generate random numbers with fixed length
const randomId = randomNumberWithFixedLength(6) // Result: 847291 (example)
const pin = randomNumberWithFixedLength(4) // Result: 7834 (example)
const code = randomNumberWithFixedLength(8) // Result: 92847361 (example)

// Working with decimal numbers
const clampedFloat = clamp(3.14159, 0, 3) // Result: 3
const floatInRange = inRange(2.5, 0, 5) // Result: true
```

### Advanced Usage Examples

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

// Create a bounded slider component value
class BoundedSlider {
  private _value: number
  private _min: number
  private _max: number

  constructor(initialValue: number, min: number, max: number) {
    this._min = min
    this._max = max
    this._value = clamp(initialValue, min, max)
  }

  get value(): number {
    return this._value
  }

  set value(newValue: number) {
    this._value = clamp(newValue, this._min, this._max)
  }

  get min(): number {
    return this._min
  }

  get max(): number {
    return this._max
  }

  isAtMin(): boolean {
    return this._value === this._min
  }

  isAtMax(): boolean {
    return this._value === this._max
  }

  increment(step: number = 1): void {
    this.value = this._value + step
  }

  decrement(step: number = 1): void {
    this.value = this._value - step
  }
}

// Usage
const volumeSlider = new BoundedSlider(50, 0, 100)
volumeSlider.increment(30) // value becomes 80
volumeSlider.increment(30) // value becomes 100 (clamped)
console.log(volumeSlider.isAtMax()) // true

// Validate user input with ranges
const validateUserInput = (input: number, fieldName: string) => {
  const validationRules: Record<string, [number, number]> = {
    age: [0, 150],
    score: [0, 100],
    temperature: [-273.15, 1000],
    percentage: [0, 100],
  }

  const [min, max] = validationRules[fieldName] || [
    Number.NEGATIVE_INFINITY,
    Number.POSITIVE_INFINITY,
  ]

  if (!inRange(input, min, max)) {
    throw new Error(
      `${fieldName} must be between ${min} and ${max}, got ${input}`
    )
  }

  return input
}

// Examples
try {
  const age = validateUserInput(25, "age") // Valid: 25
  const score = validateUserInput(105, "score") // Throws error
} catch (error) {
  console.error(error.message)
}

// Create a progress bar with clamped values
class ProgressBar {
  private progress: number = 0

  setProgress(value: number): void {
    this.progress = clamp(value, 0, 100)
  }

  increment(amount: number = 1): void {
    this.setProgress(this.progress + amount)
  }

  getProgress(): number {
    return this.progress
  }

  getProgressRatio(): number {
    return this.progress / 100
  }

  isComplete(): boolean {
    return this.progress === 100
  }

  render(): string {
    const filled = Math.round(this.progress / 5) // 20 character bar
    const empty = 20 - filled
    return `[${"â–ˆ".repeat(filled)}${" ".repeat(empty)}] ${this.progress}%`
  }
}

// Usage
const progressBar = new ProgressBar()
progressBar.setProgress(75)
console.log(progressBar.render()) // [â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆ     ] 75%
```

### Mathematical Operations

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

// Normalize values to a specific range
const normalize = (
  value: number,
  fromMin: number,
  fromMax: number,
  toMin: number,
  toMax: number
): number => {
  // First normalize to 0-1 range
  const normalized = (value - fromMin) / (fromMax - fromMin)
  // Then scale to target range and clamp
  return clamp(normalized * (toMax - toMin) + toMin, toMin, toMax)
}

// Examples
const score = normalize(75, 0, 100, 0, 10) // Convert 75% to 7.5/10 scale
const temp = normalize(25, 0, 40, 32, 104) // Convert 25Â°C to Fahrenheit range

// Create safe mathematical operations
const safeDivision = (
  dividend: number,
  divisor: number,
  min: number = Number.NEGATIVE_INFINITY,
  max: number = Number.POSITIVE_INFINITY
): number => {
  if (divisor === 0) {
    throw new Error("Division by zero")
  }

  const result = dividend / divisor
  return clamp(result, min, max)
}

// Percentage calculations with bounds
const calculatePercentage = (part: number, whole: number): number => {
  if (whole === 0) return 0
  const percentage = (part / whole) * 100
  return clamp(percentage, 0, 100)
}

// Example: Calculate completion percentage
const totalTasks = 10
const completedTasks = 8
const completion = calculatePercentage(completedTasks, totalTasks) // 80%

// Safe array indexing
const safeArrayAccess = <T>(array: T[], index: number): T | undefined => {
  const clampedIndex = clamp(Math.floor(index), 0, array.length - 1)
  return array[clampedIndex]
}

const items = ["a", "b", "c", "d", "e"]
const item = safeArrayAccess(items, 10) // Returns 'e' instead of undefined
```

### Form Validation Examples

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

// Form field validators
const validators = {
  age: (value: number) => ({
    isValid: inRange(value, 0, 150),
    normalizedValue: clamp(value, 0, 150),
    errorMessage: inRange(value, 0, 150)
      ? null
      : "Age must be between 0 and 150",
  }),

  percentage: (value: number) => ({
    isValid: inRange(value, 0, 100),
    normalizedValue: clamp(value, 0, 100),
    errorMessage: inRange(value, 0, 100)
      ? null
      : "Percentage must be between 0 and 100",
  }),

  rating: (value: number) => ({
    isValid: inRange(value, 1, 5),
    normalizedValue: clamp(value, 1, 5),
    errorMessage: inRange(value, 1, 5)
      ? null
      : "Rating must be between 1 and 5",
  }),
}

// Usage in form handling
const handleFormInput = (
  fieldName: keyof typeof validators,
  inputValue: string
) => {
  const numericValue = parseFloat(inputValue)

  if (isNaN(numericValue)) {
    return { isValid: false, errorMessage: "Must be a valid number" }
  }

  return validators[fieldName](numericValue)
}

// Example usage
const ageValidation = handleFormInput("age", "25")
console.log(ageValidation) // { isValid: true, normalizedValue: 25, errorMessage: null }

const invalidAge = handleFormInput("age", "200")
console.log(invalidAge) // { isValid: false, normalizedValue: 150, errorMessage: 'Age must be between 0 and 150' }
```

### Gaming and Animation Examples

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

// Game character stats with bounds
class Character {
  private _health: number
  private _mana: number

  constructor(private maxHealth: number = 100, private maxMana: number = 50) {
    this._health = maxHealth
    this._mana = maxMana
  }

  get health(): number {
    return this._health
  }

  get mana(): number {
    return this._mana
  }

  takeDamage(amount: number): void {
    this._health = clamp(this._health - amount, 0, this.maxHealth)
  }

  heal(amount: number): void {
    this._health = clamp(this._health + amount, 0, this.maxHealth)
  }

  useMana(amount: number): boolean {
    if (this._mana >= amount) {
      this._mana = clamp(this._mana - amount, 0, this.maxMana)
      return true
    }
    return false
  }

  restoreMana(amount: number): void {
    this._mana = clamp(this._mana + amount, 0, this.maxMana)
  }

  isAlive(): boolean {
    return this._health > 0
  }

  canCastSpell(manaCost: number): boolean {
    return inRange(manaCost, 0, this._mana)
  }

  getHealthPercentage(): number {
    return (this._health / this.maxHealth) * 100
  }
}

// Animation easing with clamped values
const easeInOut = (t: number): number => {
  const clampedT = clamp(t, 0, 1)
  return clampedT < 0.5
    ? 2 * clampedT * clampedT
    : -1 + (4 - 2 * clampedT) * clampedT
}

// Safe color channel manipulation
const adjustColorChannel = (channel: number, adjustment: number): number => {
  return clamp(channel + adjustment, 0, 255)
}

const adjustColor = (r: number, g: number, b: number, brightness: number) => ({
  r: adjustColorChannel(r, brightness),
  g: adjustColorChannel(g, brightness),
  b: adjustColorChannel(b, brightness),
})
```

### Error Handling

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

try {
  // These will throw errors due to invalid input types
  clamp("not a number" as any, 0, 10)
} catch (error) {
  console.error(error.message) // "All arguments must be numbers"
}

try {
  // This will throw an error due to invalid bounds
  clamp(5, 10, 0) // lower bound > upper bound
} catch (error) {
  console.error(error.message) // "Lower bound must be less than or equal to upper bound"
}

// Safe number operations with validation
const safeClamp = (value: unknown, lower: number, upper: number): number => {
  if (typeof value !== "number" || isNaN(value)) {
    throw new Error("Value must be a valid number")
  }

  if (typeof lower !== "number" || typeof upper !== "number") {
    throw new Error("Bounds must be valid numbers")
  }

  return clamp(value, lower, upper)
}

// Input sanitization
const sanitizeNumber = (
  input: unknown,
  min: number,
  max: number,
  defaultValue: number
): number => {
  try {
    const num = Number(input)
    if (isNaN(num)) return defaultValue
    return clamp(num, min, max)
  } catch {
    return defaultValue
  }
}

// Example usage
const userInput = sanitizeNumber("abc", 0, 100, 50) // Returns 50
const validInput = sanitizeNumber("75", 0, 100, 50) // Returns 75
```

## API Reference

### `clamp(number: number, lower: number, upper: number): number`

Clamps a number within the inclusive lower and upper bounds.

**Parameters:**

- `number` - The number to clamp
- `lower` - The lower bound (inclusive)
- `upper` - The upper bound (inclusive)

**Returns:** `number` - The clamped number

**Throws:** `Error` when:

- Any argument is not a number
- Lower bound is greater than upper bound

**Examples:**

```typescript
clamp(15, 0, 10) // Returns: 10
clamp(-5, 0, 10) // Returns: 0
clamp(5, 0, 10) // Returns: 5
clamp(3.14, 0, 3) // Returns: 3
```

### `inRange(number: number, lower: number, upper: number): boolean`

Checks if a number is within the inclusive range.

**Parameters:**

- `number` - The number to check
- `lower` - The lower bound (inclusive)
- `upper` - The upper bound (inclusive)

**Returns:** `boolean` - true if the number is within the range, false otherwise

**Throws:** `Error` when:

- Any argument is not a number
- Lower bound is greater than upper bound

**Examples:**

```typescript
inRange(5, 0, 10) // Returns: true
inRange(15, 0, 10) // Returns: false
inRange(-5, 0, 10) // Returns: false
inRange(0, 0, 10) // Returns: true (inclusive)
inRange(10, 0, 10) // Returns: true (inclusive)
```

### `convertToInt(data: any): number`

Safely converts any value to an integer.

**Parameters:**

- `data` - The value to convert to integer (can be string, number, etc.)

**Returns:** `number` - The converted integer value

**Throws:** `Error` when:

- Input is NaN
- Input is null or undefined

**Examples:**

```typescript
convertToInt("123") // Returns: 123
convertToInt("123.45") // Returns: 123
convertToInt(456.789) // Returns: 456
convertToInt("0") // Returns: 0
convertToInt("-42") // Returns: -42
```

### `convertToTwoDecimalInt(data: any): number`

Converts any value to a number with exactly 2 decimal places.

**Parameters:**

- `data` - The value to convert (can be string, number, etc.)

**Returns:** `number` - The converted number with 2 decimal places

**Throws:** `Error` when:

- Input is NaN
- Input is null or undefined

**Examples:**

```typescript
convertToTwoDecimalInt("123.456") // Returns: 123.46
convertToTwoDecimalInt(99.999) // Returns: 100.00
convertToTwoDecimalInt("19.1") // Returns: 19.10
convertToTwoDecimalInt(42) // Returns: 42.00
```

### `randomNumberWithFixedLength(length: number): number`

Generates a random number with a specific number of digits.

**Parameters:**

- `length` - The number of digits the random number should have (must be positive integer)

**Returns:** `number` - A random number with exactly the specified number of digits

**Throws:** `Error` when length is not a positive integer

**Examples:**

```typescript
randomNumberWithFixedLength(4) // Returns: 7834 (example)
randomNumberWithFixedLength(6) // Returns: 847291 (example)
randomNumberWithFixedLength(1) // Returns: 7 (example)
randomNumberWithFixedLength(8) // Returns: 92847361 (example)
```

## Best Practices

1. **Always validate input types**: Use TypeScript or runtime checks to ensure number inputs
2. **Use meaningful bounds**: Choose bounds that make sense for your domain
3. **Consider edge cases**: Handle NaN, Infinity, and boundary values appropriately
4. **Document expected ranges**: Make range expectations clear in your API documentation
5. **Use for user input validation**: Clamp and validate user inputs before processing
6. **Combine with type guards**: Use with TypeScript type guards for better type safety

## Common Use Cases

### UI Component Values

```typescript
import { clamp, inRange } from "@digicroz/js-kit/number"

// Slider component
class Slider {
  constructor(private value: number, private min: number, private max: number) {
    this.value = clamp(value, min, max)
  }

  setValue(newValue: number): void {
    this.value = clamp(newValue, this.min, this.max)
  }

  isValid(value: number): boolean {
    return inRange(value, this.min, this.max)
  }
}
```

### Configuration Validation

```typescript
interface ServerConfig {
  port: number
  maxConnections: number
  timeout: number
}

const validateConfig = (config: Partial<ServerConfig>): ServerConfig => ({
  port: clamp(config.port || 3000, 1024, 65535),
  maxConnections: clamp(config.maxConnections || 100, 1, 10000),
  timeout: clamp(config.timeout || 30000, 1000, 300000),
})
```

### Mathematical Computations

```typescript
// Safe percentage calculations
const calculateProgress = (current: number, total: number): number => {
  if (total <= 0) return 0
  const progress = (current / total) * 100
  return clamp(progress, 0, 100)
}

// Normalize scores
const normalizeScore = (
  score: number,
  minScore: number,
  maxScore: number
): number => {
  return clamp((score - minScore) / (maxScore - minScore), 0, 1)
}
```

## Performance Considerations

- **Minimal overhead**: Functions use native Math.min/Math.max for optimal performance
- **Type checking**: Input validation adds minimal overhead but ensures safety
- **No allocations**: Functions don't create objects or arrays, just return numbers
- **Inlinable**: Small functions that can be inlined by JavaScript engines

## License

This module is part of the @digicroz/js-kit package.
