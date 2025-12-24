# @digicroz/js-kit

> **Modern TypeScript utility library with tree-shaking support** - Lightweight, fully-typed utilities for arrays, strings, numbers, slugs, enums, sleep, time, and environment detection. A modern alternative to lodash with zero dependencies and 100% test coverage.

[![npm version](https://img.shields.io/npm/v/@digicroz/js-kit.svg)](https://www.npmjs.com/package/@digicroz/js-kit)
[![npm downloads](https://img.shields.io/npm/dm/@digicroz/js-kit.svg)](https://www.npmjs.com/package/@digicroz/js-kit)
[![Bundle Size](https://img.shields.io/bundlephobia/minzip/@digicroz/js-kit)](https://bundlephobia.com/package/@digicroz/js-kit)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen.svg)](https://github.com/digicroz/js-kit)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Tree Shakable](https://img.shields.io/badge/Tree--Shakable-✓-brightgreen.svg)](https://webpack.js.org/guides/tree-shaking/)

**@digicroz/js-kit** is a modern, lightweight TypeScript utility library designed for developers who need reliable, type-safe helper functions without the bloat. Perfect for React, Vue, Angular, Node.js, and any JavaScript/TypeScript project.

**Keywords**: typescript utilities, javascript helpers, lodash alternative, tree-shakeable utils, zero dependencies, array utils, string utils, slug generator, enum utilities, case conversion, sleep promises, time utilities, environment detection

## 🌟 Why Choose @digicroz/js-kit?

- **🎯 Zero Dependencies** - No bloat, just pure utilities
- **📦 Tiny Bundle Size** - Tree-shakeable ESM modules, import only what you need
- **💯 100% Test Coverage** - 211 comprehensive tests ensure reliability
- **🔒 Type-Safe** - Full TypeScript support with excellent IntelliSense
- **⚡ Modern & Fast** - Built with modern JavaScript standards (ESM, CJS support)
- **🌐 Universal** - Works in Node.js, browsers, React Native, and web workers
- **🆚 Better than lodash** - Smaller, faster, more modern, with better TypeScript support
- **📝 Well Documented** - Comprehensive JSDoc comments and examples

## 🌐 Environment Compatibility

This library is designed to work across multiple JavaScript environments:

- **✅ `@digicroz/js-kit`** - Universal utilities that work in **Node.js**, **Browser**, and **Web Workers**
- ** Individual imports** - `@digicroz/js-kit/module/function` for maximum tree-shaking

## Features

- 🚀 **TypeScript Support** - Full TypeScript support with type definitions
- 📦 **Tree Shakable** - Import only what you need
- 🧪 **100% Test Coverage** - 211 tests with comprehensive coverage across all modules
- 📖 **Well Documented** - JSDoc comments for all functions
- 🔧 **Modern Build** - Built with tsup for optimal bundling
- 💡 **Excellent IDE Support** - Full auto-completion and IntelliSense support
- 🌐 **Cross-Platform** - Works in Node.js, browsers, and web workers

## Installation

```bash
npm install @digicroz/js-kit
```

**Alternative package managers:**

```bash
# Yarn
yarn add @digicroz/js-kit

# pnpm
pnpm add @digicroz/js-kit

# Bun
bun add @digicroz/js-kit
```

## Usage

### Universal Modules

Import universal modules that work in **Node.js**, **Browser**, and **Web Workers**:

```typescript
import {
  chunk,
  capitalize,
  clamp,
  sleep,
  convertToSeconds,
  randomStringWithFixedLength,
  truncateText,
  convertToInt,
  getUnixTimestamp,
  isNodeEnvironment,
  convertToSlug,
  parseEnumValue,
  toSnakeCase,
  toCamelCase,
} from "@digicroz/js-kit"

// Array utilities
const chunkedArray = chunk([1, 2, 3, 4, 5], 2)
// Result: [[1, 2], [3, 4], [5]]

// String utilities
const capitalizedString = capitalize("hello world")
// Result: "Hello world"

const randomId = randomStringWithFixedLength(8)
// Result: "a7b9c2d1" (example)

const truncated = truncateText({ text: "This is a long text", maxLength: 10 })
// Result: "This is a..."

// Number utilities
const clampedNumber = clamp(15, 0, 10)
// Result: 10

const safeInt = convertToInt("123.45")
// Result: 123

// Sleep utilities
await sleep({ seconds: 2, milliseconds: 500 }) // Sleep for 2.5 seconds

// Time utilities
const seconds = convertToSeconds({ minutes: 5, seconds: 30 })
// Result: 330 (seconds)

const timestamp = getUnixTimestamp()
// Result: current timestamp in seconds

// Environment utilities
const isNode = isNodeEnvironment()
// Result: true if running in Node.js

// Slug utilities
const slug = convertToSlug("Hello World!")
// Result: "hello-world"

// Enum utilities
const Status = ["active", "inactive"] as const
const status = parseEnumValue(Status, "active")
// Result: 'active'

// Case conversion utilities
const snakeCase = toSnakeCase("myVariableName")
// Result: "my_variable_name"

const camelCase = toCamelCase("my_variable_name")
// Result: "myVariableName"
```

### Tree-shaking Support

You can also import individual functions for optimal tree-shaking:

```typescript
// Universal utilities - individual imports
import { chunk } from "@digicroz/js-kit/array"
import {
  capitalize,
  truncateText,
  toSnakeCase,
  toCamelCase,
} from "@digicroz/js-kit/string"
import { clamp, convertToInt } from "@digicroz/js-kit/number"
import { sleep, sleepMs } from "@digicroz/js-kit/sleep"
import { convertToSeconds, getUnixTimestamp } from "@digicroz/js-kit/time"
import { isNodeEnvironment, getEnvironment } from "@digicroz/js-kit/utils"
import {
  convertToSlug,
  isValidSlug,
  generateUniqueSlug,
} from "@digicroz/js-kit/slug"
import { parseEnumValue, requireEnumValue } from "@digicroz/js-kit/enum"

// Universal bundle (recommended)
import {
  chunk,
  capitalize,
  clamp,
  sleep,
  convertToSeconds,
} from "@digicroz/js-kit"
```

## 📋 Available Modules

### ✅ Universal Modules (Node.js + Browser + Web Workers)

| Module   | Functions                                                                                                                                                      | Description                                                    |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| `array`  | `chunk`                                                                                                                                                        | Split arrays into chunks of specified size                     |
| `string` | `capitalize`, `capitalizeWords`, `randomStringWithFixedLength`, `truncateText`, `toSnakeCase`, `toCamelCase`, `objectKeysToSnakeCase`, `objectKeysToCamelCase` | String manipulation, formatting, and case conversion utilities |
| `number` | `clamp`, `inRange`, `convertToInt`, `convertToTwoDecimalInt`, `randomNumberWithFixedLength`                                                                    | Number utilities including range operations                    |
| `slug`   | `isValidSlug`, `convertToSlug`, `generateUniqueSlug`, `zodSlugValidation`, `zodSlugTransform`, `slugSchema`, `autoSlugSchema`                                  | URL-safe slug generation and validation with Zod support       |
| `enum`   | `parseEnumValue`, `requireEnumValue`                                                                                                                           | Type-safe enum parsing and validation                          |
| `sleep`  | `sleep`, `sleepMs`, `sleepSeconds`, `sleepMinutes`, `sleepUntil`                                                                                               | Promise-based sleep with flexible time options                 |
| `time`   | `convertToSeconds`, `getUnixTimestamp`, `getUnixTimestampMs`                                                                                                   | Time conversion and timestamp utilities                        |
| `utils`  | `isNodeEnvironment`, `isBrowserEnvironment`, `isWebWorkerEnvironment`, `getEnvironment`, `assertNodeEnvironment`, `assertBrowserEnvironment`                   | Environment detection and assertions                           |
| `types`  | `Prettify`                                                                                                                                                     | Utility types for TypeScript development                       |

## TypeScript Configuration

For optimal compatibility with this package, ensure your `tsconfig.json` uses modern module resolution:

```json
{
  "compilerOptions": {
    "moduleResolution": "bundler", // or "node16"/"nodenext"
    "module": "ESNext", // or "Node16"
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "skipLibCheck": true
  }
}
```

### Troubleshooting Import Issues

If you encounter module resolution errors like:

```
Cannot find module '@digicroz/js-kit/string/capitalize' or its corresponding type declarations
```

Try these solutions:

1. **Update your TypeScript configuration** to use modern module resolution (see above)
2. **Ensure you're using a recent Node.js version** (16+ recommended)
3. **Copy the example configuration** from `example-tsconfig-for-consumers.json` in this package
4. **As a workaround**, you can import directly from the dist folder:
   ```typescript
   import { capitalize } from "@digicroz/js-kit/dist/string/capitalize.js"
   ```

### IDE Support

This package provides excellent IDE support with:

- **Auto-completion** for all functions and their parameters
- **Type checking** with full TypeScript support
- **JSDoc documentation** shown in hover tooltips
- **Auto-import** suggestions when typing function names

## API Reference

### 📚 Package Documentation

For comprehensive documentation with examples, advanced usage patterns, and best practices, see the individual package documentation:

- **[🔢 Array Utilities](./src/array/array.md)** - Array manipulation and chunking utilities
- **[🔢 Number Utilities](./src/number/number.md)** - Number clamping, conversion, and range validation
- **[🔗 Slug Utilities](./src/slug/slug.md)** - URL-safe slug generation and validation
- **[📋 Enum Utilities](./src/enum/enum.md)** - Type-safe enum parsing and validation
- **[⏰ Sleep Utilities](./src/sleep/sleep.md)** - Advanced sleep and timing functions
- **[📝 String Utilities](./src/string/string.md)** - String manipulation, formatting, and case conversion
- **[⏰ Time Utilities](./src/time/time.md)** - Time conversion and duration utilities
- **[🌐 Environment Utilities](./src/utils/utils.md)** - Environment detection and cross-platform utilities

### Quick Reference

#### Array Utilities

- `chunk<T>(array: T[], size: number): T[][]` - Splits an array into chunks of a specified size

#### String Utilities

- `capitalize(str: string): string` - Capitalizes the first letter of a string
- `capitalizeWords(str: string): string` - Capitalizes the first letter of each word
- `randomStringWithFixedLength(length: number): string` - Generates a random string with fixed length
- `truncateText(options: TruncateTextOptions): string` - Truncates text with customizable options
- `toSnakeCase<T extends string>(value: T): ToSnakeCaseResult<T>` - Converts camelCase to snake_case
- `toCamelCase<T extends string>(str: T): ToCamelCaseResult<T>` - Converts snake_case to camelCase
- `objectKeysToSnakeCase<T>(obj: T): ObjectKeysToSnakeCaseResult<T>` - Recursively converts object keys to snake_case
- `objectKeysToCamelCase<T>(obj: T): ObjectKeysToCamelCaseResult<T>` - Recursively converts object keys to camelCase

#### Number Utilities

- `clamp(number: number, lower: number, upper: number): number` - Clamps a number within bounds
- `inRange(number: number, lower: number, upper: number): boolean` - Checks if number is in range
- `convertToInt(data: any): number` - Safely converts any value to integer
- `convertToTwoDecimalInt(data: any): number` - Converts to number with 2 decimal places
- `randomNumberWithFixedLength(length: number): number` - Generates random number with fixed length

#### Slug Utilities

- `isValidSlug(slug: string): boolean` - Validates if a string is a valid URL slug
- `convertToSlug(text: string, options?): string` - Converts text to a URL-safe slug
- `generateUniqueSlug(baseText: string, existingSlugs: string[]): string` - Generates a unique slug
- `zodSlugValidation(message?: string)` - Zod validation for slug format
- `zodSlugTransform(options?)` - Zod transform that converts text to slug
- `slugSchema` - Pre-configured Zod schemas for slug validation
- `autoSlugSchema` - Pre-configured Zod schemas for automatic slug generation

#### Enum Utilities

- `parseEnumValue<T>(enumArray: T, value: string): T[number] | undefined` - Safely parses enum value
- `requireEnumValue<T>(enumArray: T, value: string): T[number]` - Parses enum value or throws error

#### Sleep Utilities

- `sleep(params: TSleepParams): Promise<void>` - Advanced sleep with flexible options
- `sleepMs(ms: number): Promise<void>` - Sleep for milliseconds
- `sleepSeconds(seconds: number): Promise<void>` - Sleep for seconds
- `sleepMinutes(minutes: number): Promise<void>` - Sleep for minutes
- `sleepUntil(unixTimestamp: number): Promise<void>` - Sleep until timestamp

#### Time Utilities

- `convertToSeconds(options): number` - Converts time units to seconds
- `getUnixTimestamp(): number` - Gets current Unix timestamp in seconds
- `getUnixTimestampMs(): number` - Gets current Unix timestamp in milliseconds

#### Environment Utilities

- `isNodeEnvironment(): boolean` - Checks if running in Node.js
- `isBrowserEnvironment(): boolean` - Checks if running in browser
- `isWebWorkerEnvironment(): boolean` - Checks if running in web worker
- `getEnvironment(): string` - Gets current environment type
- `assertNodeEnvironment(): void` - Asserts Node.js environment
- `assertBrowserEnvironment(): void` - Asserts browser environment

#### Type Utilities

- `Prettify<T>` - Utility type for better TypeScript intellisense

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Watch mode for development
npm run dev

# Type checking
npm run type-check

# Run tests
npm run test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 👤 Author

**Adarsh Hatkar**

- GitHub: [@AdarshHatkar](https://github.com/AdarshHatkar)
- Organization: [@digicroz](https://github.com/digicroz)

## 🔗 Links

- [NPM Package](https://www.npmjs.com/package/@digicroz/js-kit)
- [GitHub Repository](https://github.com/digicroz/js-kit)
- [Issue Tracker](https://github.com/digicroz/js-kit/issues)
- [Changelog](https://github.com/digicroz/js-kit/releases)

## ⭐ Show Your Support

Give a ⭐️ if this project helped you!

## 📄 License

MIT © [Adarsh Hatkar](https://github.com/AdarshHatkar)

Copyright (c) 2025 Adarsh Hatkar
