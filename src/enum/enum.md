# Enum Utilities

Type-safe enum parsing and validation utilities for TypeScript const arrays.

## Overview

The enum utilities provide a type-safe way to work with TypeScript const arrays as enums. These utilities help validate and parse string values against a predefined set of allowed values, with full type inference.

## Functions

### `parseEnumValue`

Safely parses a string value against an enum array and returns the typed value if valid, or `undefined` if invalid.

**Signature:**

```typescript
const parseEnumValue = <T extends readonly string[]>(
  enumArray: T,
  value: string
): T[number] | undefined
```

**Parameters:**

- `enumArray` - A readonly array of string literals (const array)
- `value` - The string value to validate

**Returns:**

- The typed enum value if found in the array
- `undefined` if the value is not in the array

**Examples:**

```typescript
import { parseEnumValue } from "@digicroz/js-kit/enum"

// Define an enum as a const array
const UserStatus = ["active", "inactive", "pending", "suspended"] as const

// Valid value
const status1 = parseEnumValue(UserStatus, "active")
// Result: 'active' (type: 'active' | 'inactive' | 'pending' | 'suspended')

// Invalid value
const status2 = parseEnumValue(UserStatus, "unknown")
// Result: undefined

// Use in validation
function validateStatus(input: string) {
  const status = parseEnumValue(UserStatus, input)
  if (status) {
    console.log(`Valid status: ${status}`)
  } else {
    console.log("Invalid status provided")
  }
}

// API response parsing
const apiResponse = { status: "active" }
const validatedStatus = parseEnumValue(UserStatus, apiResponse.status)

if (validatedStatus) {
  // TypeScript knows validatedStatus is one of the enum values
  console.log(`User is ${validatedStatus}`)
}
```

### `requireEnumValue`

Parses a string value against an enum array and returns the typed value if valid, or throws an error if invalid. Use this when you need strict validation.

**Signature:**

```typescript
const requireEnumValue = <T extends readonly string[]>(
  enumArray: T,
  value: string
): T[number]
```

**Parameters:**

- `enumArray` - A readonly array of string literals (const array)
- `value` - The string value to validate

**Returns:**

- The typed enum value if found in the array

**Throws:**

- `Error` with message `"Invalid enum value: {value}"` if the value is not in the array

**Examples:**

```typescript
import { requireEnumValue } from "@digicroz/js-kit/enum"

const OrderStatus = [
  "pending",
  "processing",
  "shipped",
  "delivered",
  "cancelled",
] as const

// Valid value - no error
const status1 = requireEnumValue(OrderStatus, "shipped")
// Result: 'shipped'

// Invalid value - throws error
try {
  const status2 = requireEnumValue(OrderStatus, "unknown")
} catch (error) {
  console.error(error.message) // "Invalid enum value: unknown"
}

// Use in API route handlers
function updateOrderStatus(orderId: string, newStatus: string) {
  // Will throw if status is invalid
  const validatedStatus = requireEnumValue(OrderStatus, newStatus)

  // TypeScript knows validatedStatus is one of the enum values
  return updateOrder(orderId, validatedStatus)
}

// Form validation
function handleFormSubmit(formData: FormData) {
  const priority = formData.get("priority") as string

  try {
    const validPriority = requireEnumValue(
      ["low", "medium", "high"] as const,
      priority
    )
    submitTask({ priority: validPriority })
  } catch (error) {
    showError("Invalid priority selected")
  }
}
```

## Common Use Cases

### API Request Validation

```typescript
import { parseEnumValue, requireEnumValue } from "@digicroz/js-kit/enum"

const HttpMethod = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const

function makeRequest(method: string, url: string) {
  const validMethod = requireEnumValue(HttpMethod, method.toUpperCase())
  return fetch(url, { method: validMethod })
}
```

### Form Validation

```typescript
const Priority = ["low", "medium", "high"] as const
const Category = ["bug", "feature", "docs", "test"] as const

function validateTicket(data: { priority: string; category: string }) {
  const priority = parseEnumValue(Priority, data.priority)
  const category = parseEnumValue(Category, data.category)

  if (!priority || !category) {
    return { valid: false, error: "Invalid priority or category" }
  }

  return { valid: true, priority, category }
}
```

### Database Enum Validation

```typescript
const UserRole = ["admin", "moderator", "user", "guest"] as const

function assignRole(userId: string, role: string) {
  // Ensures only valid roles are stored in the database
  const validRole = requireEnumValue(UserRole, role)

  return database.users.update({
    where: { id: userId },
    data: { role: validRole },
  })
}
```

### Query Parameter Validation

```typescript
const SortOrder = ["asc", "desc"] as const
const SortBy = ["date", "name", "price", "rating"] as const

function buildQuery(params: URLSearchParams) {
  const sortBy = parseEnumValue(SortBy, params.get("sortBy") ?? "date")
  const order = parseEnumValue(SortOrder, params.get("order") ?? "asc")

  return {
    sortBy: sortBy ?? "date",
    order: order ?? "asc",
  }
}
```

### Configuration Validation

```typescript
const Environment = ["development", "staging", "production"] as const
const LogLevel = ["debug", "info", "warn", "error"] as const

function loadConfig(env: string) {
  const environment = requireEnumValue(Environment, env)

  const config = {
    env: environment,
    logLevel: environment === "production" ? "error" : "debug",
  }

  return config
}
```

## Type Safety

Both utilities provide full TypeScript type inference:

```typescript
const Status = ["active", "inactive"] as const

// Type: 'active' | 'inactive' | undefined
const result1 = parseEnumValue(Status, "active")

// Type: 'active' | 'inactive'
const result2 = requireEnumValue(Status, "active")

// TypeScript will show autocomplete for these values
if (result1 === "active") {
  // ✓ TypeScript knows this is valid
}
```

## When to Use

### Use `parseEnumValue` when:

- You want to handle invalid values gracefully
- You need optional validation (returning `undefined` for invalid values)
- You're parsing user input where invalid values are expected
- You want to provide default values for invalid input

### Use `requireEnumValue` when:

- Invalid values should throw errors
- You're in an error boundary or try-catch block
- You want to fail fast on invalid data
- You're validating critical data that must be correct

## Best Practices

1. **Always use `as const`** to ensure proper type inference:

   ```typescript
   // ✓ Good
   const Status = ["active", "inactive"] as const

   // ✗ Bad - loses literal types
   const Status = ["active", "inactive"]
   ```

2. **Handle `parseEnumValue` undefined case**:

   ```typescript
   const status = parseEnumValue(Status, input) ?? "active" // Default value
   ```

3. **Use in Zod schemas** for runtime validation:

   ```typescript
   import { z } from "zod"

   const Status = ["active", "inactive"] as const

   const schema = z
     .string()
     .refine((val) => parseEnumValue(Status, val) !== undefined, {
       message: "Invalid status",
     })
   ```

4. **Combine with TypeScript enums** if needed:
   ```typescript
   const StatusArray = ["active", "inactive"] as const
   type Status = (typeof StatusArray)[number] // 'active' | 'inactive'
   ```

## Related Utilities

- [String Utilities](../string/string.md) - For string manipulation
- [Slug Utilities](../slug/slug.md) - For URL-safe slug validation
