# Environment Utilities

Environment detection and assertion utilities for JavaScript/TypeScript applications across different runtime environments.

## Features

- ✅ **Full TypeScript Support** - Complete type definitions and type safety
- ✅ **Comprehensive JSDoc** - Detailed documentation for all functions
- ✅ **Cross-Platform Detection** - Support for Node.js, Browser, and Web Worker environments
- ✅ **Environment Assertions** - Built-in assertion functions for environment validation
- ✅ **Error Handling** - Custom error types for environment-specific issues
- ✅ **Zero Dependencies** - Pure JavaScript implementations

## Installation

```bash
npm install @digicroz/js-kit
```

## Usage

### Two Usage Patterns

You can use the environment utilities in two ways:

#### 1. Individual Function Imports (Recommended)

```typescript
import {
  isNodeEnvironment,
  isBrowserEnvironment,
  getEnvironment,
  assertNodeEnvironment,
} from "@digicroz/js-kit/utils"

const isNode = isNodeEnvironment() // true if running in Node.js
const environment = getEnvironment() // 'node' | 'browser' | 'webworker' | 'unknown'
```

#### 2. Package Import

```typescript
import {
  isNodeEnvironment,
  isBrowserEnvironment,
  getEnvironment,
} from "@digicroz/js-kit"

const isNode = isNodeEnvironment() // true if running in Node.js
```

### Basic Environment Detection

```typescript
import {
  isNodeEnvironment,
  isBrowserEnvironment,
  isWebWorkerEnvironment,
  getEnvironment,
} from "@digicroz/js-kit/utils"

// Check specific environments
const runningInNode = isNodeEnvironment()
console.log("Node.js:", runningInNode) // true if in Node.js

const runningInBrowser = isBrowserEnvironment()
console.log("Browser:", runningInBrowser) // true if in browser

const runningInWebWorker = isWebWorkerEnvironment()
console.log("Web Worker:", runningInWebWorker) // true if in web worker

// Get current environment as string
const currentEnv = getEnvironment()
console.log("Current environment:", currentEnv) // 'node' | 'browser' | 'webworker' | 'unknown'

// Conditional logic based on environment
if (isNodeEnvironment()) {
  console.log("Running server-side logic")
  // Use Node.js specific APIs
} else if (isBrowserEnvironment()) {
  console.log("Running client-side logic")
  // Use browser APIs like DOM, localStorage, etc.
} else if (isWebWorkerEnvironment()) {
  console.log("Running in web worker")
  // Use Web Worker APIs
}
```

### Environment Assertions

```typescript
import {
  assertNodeEnvironment,
  assertBrowserEnvironment,
  EnvironmentError,
} from "@digicroz/js-kit/utils"

// Assert specific environment requirements
try {
  assertNodeEnvironment()
  console.log("Confirmed: Running in Node.js")

  // Safe to use Node.js specific code here
  const fs = require("fs")
  const path = require("path")
} catch (error) {
  if (error instanceof EnvironmentError) {
    console.error(`Environment error: ${error.message}`)
    console.error(`Required: ${error.requiredEnvironment}`)
    console.error(`Current: ${error.currentEnvironment}`)
  }
}

try {
  assertBrowserEnvironment()
  console.log("Confirmed: Running in browser")

  // Safe to use browser APIs here
  document.getElementById("app")
  localStorage.setItem("key", "value")
} catch (error) {
  console.error("Browser environment required")
}
```

### Advanced Usage Examples

```typescript
import {
  getEnvironment,
  isNodeEnvironment,
  isBrowserEnvironment,
  EnvironmentError,
} from "@digicroz/js-kit/utils"

// Universal logging function
const createLogger = () => {
  const env = getEnvironment()

  switch (env) {
    case "node":
      // Use console for Node.js
      return console

    case "browser":
      // Enhanced browser logging
      return {
        log: (msg: string) => console.log(`[Browser] ${msg}`),
        error: (msg: string) => console.error(`[Browser] ${msg}`),
        warn: (msg: string) => console.warn(`[Browser] ${msg}`),
      }

    case "webworker":
      // Web worker logging
      return {
        log: (msg: string) => console.log(`[Worker] ${msg}`),
        error: (msg: string) => console.error(`[Worker] ${msg}`),
        warn: (msg: string) => console.warn(`[Worker] ${msg}`),
      }

    default:
      // Fallback for unknown environments
      return {
        log: () => {},
        error: () => {},
        warn: () => {},
      }
  }
}

// Storage abstraction
class UniversalStorage {
  private storage: any

  constructor() {
    if (isBrowserEnvironment()) {
      this.storage = localStorage
    } else if (isNodeEnvironment()) {
      // Use file system or memory for Node.js
      this.storage = new Map()
    } else {
      // Fallback storage
      this.storage = new Map()
    }
  }

  setItem(key: string, value: string): void {
    if (this.storage.setItem) {
      this.storage.setItem(key, value)
    } else {
      this.storage.set(key, value)
    }
  }

  getItem(key: string): string | null {
    if (this.storage.getItem) {
      return this.storage.getItem(key)
    } else {
      return this.storage.get(key) || null
    }
  }

  removeItem(key: string): void {
    if (this.storage.removeItem) {
      this.storage.removeItem(key)
    } else {
      this.storage.delete(key)
    }
  }
}

// Feature detection utility
const getAvailableFeatures = () => {
  const features: string[] = []

  if (isNodeEnvironment()) {
    features.push("filesystem", "process", "modules")
  }

  if (isBrowserEnvironment()) {
    features.push("dom", "localStorage")

    if (typeof navigator !== "undefined") {
      features.push("navigator")
    }

    if (typeof fetch !== "undefined") {
      features.push("fetch")
    }

    if ("serviceWorker" in navigator) {
      features.push("serviceWorker")
    }
  }

  if (isWebWorkerEnvironment()) {
    features.push("webworker", "importScripts")
  }

  return features
}

// Example usage
const logger = createLogger()
const storage = new UniversalStorage()
const features = getAvailableFeatures()

logger.log(`Environment: ${getEnvironment()}`)
logger.log(`Available features: ${features.join(", ")}`)

storage.setItem("environment", getEnvironment())
```

### Library Development Example

```typescript
import {
  isNodeEnvironment,
  isBrowserEnvironment,
  assertNodeEnvironment,
  EnvironmentError,
} from "@digicroz/js-kit/utils"

// Universal HTTP client
class UniversalHttpClient {
  async get(url: string): Promise<any> {
    if (isNodeEnvironment()) {
      // Use Node.js http/https modules or a library like axios
      const https = require("https")
      return new Promise((resolve, reject) => {
        https.get(url, (res: any) => {
          let data = ""
          res.on("data", (chunk: any) => (data += chunk))
          res.on("end", () => resolve(JSON.parse(data)))
          res.on("error", reject)
        })
      })
    } else if (isBrowserEnvironment()) {
      // Use fetch API
      const response = await fetch(url)
      return response.json()
    } else {
      throw new Error("HTTP client not supported in this environment")
    }
  }
}

// File system utilities (Node.js only)
class FileSystemUtils {
  constructor() {
    assertNodeEnvironment() // Will throw if not in Node.js
  }

  readFile(path: string): string {
    const fs = require("fs")
    return fs.readFileSync(path, "utf8")
  }

  writeFile(path: string, content: string): void {
    const fs = require("fs")
    fs.writeFileSync(path, content, "utf8")
  }

  fileExists(path: string): boolean {
    const fs = require("fs")
    return fs.existsSync(path)
  }
}

// Browser-specific utilities
class BrowserUtils {
  constructor() {
    if (!isBrowserEnvironment()) {
      throw new EnvironmentError(
        "BrowserUtils requires browser environment",
        "browser",
        getEnvironment()
      )
    }
  }

  getViewportSize(): { width: number; height: number } {
    return {
      width: window.innerWidth,
      height: window.innerHeight,
    }
  }

  setCookie(name: string, value: string, days: number = 7): void {
    const expires = new Date()
    expires.setTime(expires.getTime() + days * 24 * 60 * 60 * 1000)
    document.cookie = `${name}=${value};expires=${expires.toUTCString()};path=/`
  }

  getCookie(name: string): string | null {
    const nameEQ = name + "="
    const ca = document.cookie.split(";")

    for (let i = 0; i < ca.length; i++) {
      let c = ca[i]
      while (c.charAt(0) === " ") c = c.substring(1, c.length)
      if (c.indexOf(nameEQ) === 0) return c.substring(nameEQ.length, c.length)
    }

    return null
  }
}

// Usage examples
try {
  const httpClient = new UniversalHttpClient()
  const data = await httpClient.get("https://api.example.com/data")
  console.log("Fetched data:", data)
} catch (error) {
  console.error("HTTP request failed:", error)
}

try {
  const fileUtils = new FileSystemUtils() // Only works in Node.js
  const content = fileUtils.readFile("./config.json")
  console.log("File content:", content)
} catch (error) {
  if (error instanceof EnvironmentError) {
    console.log("File system operations not available in this environment")
  }
}

try {
  const browserUtils = new BrowserUtils() // Only works in browser
  const viewport = browserUtils.getViewportSize()
  console.log("Viewport size:", viewport)
} catch (error) {
  console.log("Browser utilities not available")
}
```

### Framework Integration

```typescript
import {
  getEnvironment,
  isNodeEnvironment,
  isBrowserEnvironment,
} from "@digicroz/js-kit/utils"

// React hook for environment detection
const useEnvironment = () => {
  const [environment, setEnvironment] = useState<string>("unknown")

  useEffect(() => {
    setEnvironment(getEnvironment())
  }, [])

  return {
    environment,
    isNode: environment === "node",
    isBrowser: environment === "browser",
    isWebWorker: environment === "webworker",
  }
}

// Vue.js plugin
const EnvironmentPlugin = {
  install(app: any) {
    app.config.globalProperties.$environment = getEnvironment()
    app.config.globalProperties.$isNode = isNodeEnvironment()
    app.config.globalProperties.$isBrowser = isBrowserEnvironment()
  },
}

// Next.js utility
export const getServerSideProps = async () => {
  if (!isNodeEnvironment()) {
    throw new Error("getServerSideProps must run on server")
  }

  // Server-side logic here
  const data = await fetchServerData()

  return {
    props: {
      data,
      environment: "node",
    },
  }
}

// Express.js middleware
const environmentMiddleware = (req: any, res: any, next: any) => {
  req.environment = getEnvironment()
  req.isServer = isNodeEnvironment()
  next()
}
```

## API Reference

### `isNodeEnvironment(): boolean`

Determines if the current environment is Node.js.

**Returns:** `boolean` - true if running in Node.js, false otherwise

**Examples:**

```typescript
const isNode = isNodeEnvironment()
if (isNode) {
  // Use Node.js specific APIs
  const fs = require("fs")
}
```

### `isBrowserEnvironment(): boolean`

Determines if the current environment is a browser.

**Returns:** `boolean` - true if running in a browser, false otherwise

**Examples:**

```typescript
const isBrowser = isBrowserEnvironment()
if (isBrowser) {
  // Use browser APIs
  document.getElementById("app")
}
```

### `isWebWorkerEnvironment(): boolean`

Determines if the current environment is a web worker.

**Returns:** `boolean` - true if running in a web worker, false otherwise

**Examples:**

```typescript
const isWorker = isWebWorkerEnvironment()
if (isWorker) {
  // Use Web Worker APIs
  importScripts("script.js")
}
```

### `getEnvironment(): string`

Gets the current runtime environment.

**Returns:** `'node' | 'browser' | 'webworker' | 'unknown'`

**Examples:**

```typescript
const env = getEnvironment()
switch (env) {
  case "node":
    console.log("Running in Node.js")
    break
  case "browser":
    console.log("Running in browser")
    break
  case "webworker":
    console.log("Running in web worker")
    break
  default:
    console.log("Unknown environment")
}
```

### `assertNodeEnvironment(): void`

Asserts that the current environment is Node.js.

**Throws:** `EnvironmentError` if not running in Node.js

**Examples:**

```typescript
try {
  assertNodeEnvironment()
  // Safe to use Node.js APIs
  const path = require("path")
} catch (error) {
  console.error("Node.js environment required")
}
```

### `assertBrowserEnvironment(): void`

Asserts that the current environment is a browser.

**Throws:** `EnvironmentError` if not running in a browser

**Examples:**

```typescript
try {
  assertBrowserEnvironment()
  // Safe to use browser APIs
  localStorage.setItem("key", "value")
} catch (error) {
  console.error("Browser environment required")
}
```

### `EnvironmentError`

Custom error class for environment-related issues.

**Properties:**

- `requiredEnvironment: string` - The required environment
- `currentEnvironment: string` - The current environment

**Examples:**

```typescript
try {
  assertNodeEnvironment()
} catch (error) {
  if (error instanceof EnvironmentError) {
    console.error(`Required: ${error.requiredEnvironment}`)
    console.error(`Current: ${error.currentEnvironment}`)
  }
}
```

## Type Definitions

```typescript
type Environment = "node" | "browser" | "webworker" | "unknown"

class EnvironmentError extends Error {
  constructor(
    message: string,
    public readonly requiredEnvironment: string,
    public readonly currentEnvironment: string
  )
}

function isNodeEnvironment(): boolean
function isBrowserEnvironment(): boolean
function isWebWorkerEnvironment(): boolean
function getEnvironment(): Environment
function assertNodeEnvironment(): void
function assertBrowserEnvironment(): void
```

## Best Practices

1. **Use Early Detection**: Check environment at the start of your application
2. **Graceful Degradation**: Provide fallbacks for unsupported environments
3. **Use Assertions Sparingly**: Only assert when absolutely necessary
4. **Handle Errors Properly**: Always handle `EnvironmentError` appropriately
5. **Test All Environments**: Test your code in all target environments
6. **Document Environment Requirements**: Clearly document which environments your code supports

## Common Use Cases

### Universal Libraries

```typescript
// Create libraries that work everywhere
class UniversalStorage {
  setItem(key: string, value: string) {
    if (isBrowserEnvironment()) {
      localStorage.setItem(key, value)
    } else {
      // Use alternative storage for Node.js
    }
  }
}
```

### Conditional Imports

```typescript
// Load different modules based on environment
const loadHttpClient = async () => {
  if (isNodeEnvironment()) {
    return (await import("axios")).default
  } else {
    return fetch
  }
}
```

### Feature Detection

```typescript
// Check for specific features
const hasDOM = isBrowserEnvironment() && typeof document !== "undefined"
const hasProcess = isNodeEnvironment() && typeof process !== "undefined"
```

### SSR/CSR Logic

```typescript
// Different logic for server and client
const getData = async () => {
  if (isNodeEnvironment()) {
    // Server-side data fetching
    return await fetchFromDatabase()
  } else {
    // Client-side API call
    return await fetchFromAPI()
  }
}
```

## Performance Considerations

- **Minimal Overhead**: All detection functions use simple runtime checks
- **No External Dependencies**: Pure JavaScript implementations
- **Caching Friendly**: Results can be cached since environment doesn't change at runtime
- **Tree Shakable**: Import only the functions you need

## License

This module is part of the @digicroz/js-kit package.
