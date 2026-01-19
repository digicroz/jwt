# @digicroz/jwt

> **Production-grade JWT utilities with complete type safety, zero thrown errors, and timing-safe verification.**

[![npm version](https://img.shields.io/npm/v/@digicroz/jwt.svg)](https://www.npmjs.com/package/@digicroz/jwt)
[![npm downloads](https://img.shields.io/npm/dm/@digicroz/jwt.svg)](https://www.npmjs.com/package/@digicroz/jwt)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)
[![Test Coverage](https://img.shields.io/badge/Coverage-82%25-brightgreen.svg)](https://github.com/digicroz/jwt)
[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

A modern, type-safe JWT library for Node.js and TypeScript. Built with security-first design, comprehensive type inference, and production-ready error handling. **Never throws errors**—always returns a `Result` type for predictable error handling.

## 🌟 Features

- **🔒 Type-Safe**: Full TypeScript support with generic payload types
- **🚫 No Throw Errors**: All operations return `Result<T>` (success | error)
- **⏱️ Timing-Safe**: Protection against timing attacks on token verification
- **🧪 Fully Tested**: 79 tests with 82% coverage
- **⚡ Production-Ready**: Error types, detailed diagnostics, and error chaining
- **📦 Single Dependency**: Only depends on `jsonwebtoken`
- **🌐 Universal**: Works in Node.js and modern browsers
- **📝 Well Documented**: Comprehensive JSDoc and examples

## 🎯 Why @digicroz/jwt?

### Problem: Traditional JWT Libraries

```typescript
// Old way - Throws errors, poor type safety
try {
  const payload = await jwtVerifyAsync(token, secret)
  // payload type is unknown!
} catch (err) {
  // Handle multiple error types
}
```

### Solution: @digicroz/jwt

```typescript
// New way - Type-safe, no thrown errors
const result = await jwtVerify<CustomPayload>(token, secret)

if (result.status === "success") {
  // result.result is typed as CustomPayload!
  console.log(result.result.userId)
} else {
  // Handle specific error types
  console.error(`${result.error.code}: ${result.error.message}`)
}
```

## 📦 Installation

```bash
npm install @digicroz/jwt
```

## 🚀 Quick Start

### Verify JWT Token

```typescript
import { jwtVerify } from "@digicroz/jwt"

// Define your payload type
interface AuthPayload {
  userId: string
  email: string
  role: "admin" | "user"
}

const result = await jwtVerify<AuthPayload>(token, secret)

if (result.status === "success") {
  console.log(`User: ${result.result.userId}`)
} else {
  console.error(`Verification failed: ${result.error.code}`)
}
```

### Sign JWT Token

```typescript
import { jwtSign } from "@digicroz/jwt"

const payload = { userId: "123", role: "admin" }

// Now async!
const result = await jwtSign(payload, secret, {
  expiresIn: "1h",
  issuer: "my-app",
})

if (result.status === "success") {
  console.log(`Token: ${result.result}`)
} else {
  console.error(`Signing failed: ${result.error.message}`)
}
```

### Decode JWT Token

```typescript
import { jwtDecode } from "@digicroz/jwt"

// Decode without verification - inspect token contents
const result = jwtDecode<AuthPayload>(token)

if (result.status === "success") {
  console.log(result.result) // Payload without verification
} else {
  console.error("Invalid token structure")
}
```

## 📚 API Reference

### `jwtVerify<T>(token, secret, options?)`

Verify and decode a JWT token asynchronously.

```typescript
const result = await jwtVerify<PayloadType>(token, secret, {
  algorithms: ["HS256"],
  issuer: "my-app",
  audience: "my-api",
  ignoreExpiration: false,
  clockTolerance: 0,
})
```

**Returns**: `Promise<JwtResult<T>>`

### `jwtSign<T>(payload, secret, options?)`

Sign and create a JWT token asynchronously.

```typescript
const result = await jwtSign(payload, secret, {
  expiresIn: "24h",
  issuer: "my-app",
  subject: "user-auth",
  audience: "my-api",
  algorithm: "HS256",
})
```

**Returns**: `Promise<JwtResult<string>>`

### `jwtDecode<T>(token, options?)`

Decode a JWT token without verification.

```typescript
const result = jwtDecode<PayloadType>(token, {
  complete: false,
})
```

**Returns**: `JwtResult<T>`

## 🛡️ Error Handling

### Error Types

```typescript
import { JwtErrorType } from "@digicroz/jwt"

enum JwtErrorType {
  INVALID_TOKEN = "INVALID_TOKEN",
  EXPIRED_TOKEN = "EXPIRED_TOKEN",
  INVALID_SIGNATURE = "INVALID_SIGNATURE",
  MALFORMED_TOKEN = "MALFORMED_TOKEN",
  INVALID_ALGORITHM = "INVALID_ALGORITHM",
  VERIFICATION_FAILED = "VERIFICATION_FAILED",
  SIGNING_FAILED = "SIGNING_FAILED",
  INVALID_SECRET = "INVALID_SECRET",
  UNKNOWN_ERROR = "UNKNOWN_ERROR",
}
```

### Error Handling Patterns

```typescript
// ✅ BEST DX: Direct equality check
const result = await jwtVerify(token, secret)
if (result.status === "error") {
  // TypeScript knows result.error exists here
  console.error(`Error: ${result.error.message}`)
}

// ✅ ALSO GOOD: Check status === "success"
if (result.status === "success") {
  // TypeScript knows result.result exists here
  console.log(result.result)
}

// ✅ ALTERNATIVE: Using type guards
import { isSuccess, isError } from "@digicroz/jwt"

if (isError(result)) {
  console.error(result.error.code)
} else if (isSuccess(result)) {
  console.log(result.result)
}

// ✅ FOR COMPLEX LOGIC: Specific error handling
if (result.status === "error") {
  switch (result.error.code) {
    case JwtErrorType.EXPIRED_TOKEN:
      // Handle expired token
      break
    case JwtErrorType.INVALID_SIGNATURE:
      // Handle invalid signature
      break
    default:
    // Handle other errors
  }
}
```

## 🔐 Security Features

### Timing-Safe Comparison

Protects against timing attacks:

```typescript
import { timingSafeEqual } from "@digicroz/jwt/utils"

const isEqual = timingSafeEqual(secret1, secret2)
```

### Token Structure Validation

Quick structural validation before full verification:

```typescript
import { isValidTokenStructure } from "@digicroz/jwt/utils"

if (!isValidTokenStructure(token)) {
  console.error("Invalid token format")
}
```

## 📋 Usage Examples

### Express Middleware

```typescript
import { jwtVerify, JwtErrorType } from "@digicroz/jwt"

export async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1]

  if (!token) {
    return res.status(401).json({ error: "Missing token" })
  }

  const result = await jwtVerify(token, process.env.JWT_SECRET)

  if (result.status === "error") {
    if (result.error.code === JwtErrorType.EXPIRED_TOKEN) {
      return res.status(401).json({ error: "Token expired" })
    }
    return res.status(401).json({ error: "Invalid token" })
  }

  req.user = result.result
  next()
}
```

### Refresh Token Flow

```typescript
const refreshResult = await jwtVerify(refreshToken, process.env.REFRESH_SECRET)

if (refreshResult.status === "success") {
  // Issue new access token
  const newToken = await jwtSign(
    { userId: refreshResult.result.userId },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  )

  if (newToken.status === "success") {
    return res.json({ accessToken: newToken.result })
  }
}

return res.status(401).json({ error: "Token refresh failed" })
```

## 🧪 Testing

Run the test suite:

```bash
# Run all tests
npm run test

# Run with coverage
npm run test:coverage

# Watch mode
npm run test:watch

# UI mode
npm run test:ui
```

## 📈 Performance

- **No thrown errors**: Eliminates overhead of exception handling
- **Timing-safe verification**: Constant-time comparison prevents timing attacks
- **Tree-shakeable**: Only import what you need
- **Lightweight**: Single dependency (jsonwebtoken)

## 🔄 Migration from jwtVerifyAsync

**Before** (Old approach):

```typescript
try {
  const payload = await jwtVerifyAsync(token, secret)
} catch (err) {
  // Handle error
}
```

**After** (New approach):

```typescript
const result = await jwtVerify(token, secret)
if (result.status === "success") {
  const payload = result.result
}
```

## 📝 API Types

### JwtResult Type

```typescript
import { StdResponse } from "@digicroz/js-kit/std-response"

// Uses StandardResponse pattern
type JwtResult<T> = StdResponse<T, JwtErrorType>
```

### JwtPayload Interface

```typescript
interface JwtPayload {
  [key: string]: unknown
  iat?: number // Issued at
  exp?: number // Expiration time
  nbf?: number // Not before
  iss?: string // Issuer
  sub?: string // Subject
  aud?: string | string[] // Audience
  jti?: string // JWT ID
}
```

## 🆘 Troubleshooting

### TypeScript Error: "Type does not satisfy constraint 'JwtPayload'"

Your payload type must have an index signature:

```typescript
// ✅ Correct
interface AuthPayload extends Record<string, unknown> {
  userId: string
}

// ❌ Wrong
interface AuthPayload {
  userId: string
}
```

### "Invalid token" Error Even with Valid Token

Check these common issues:

1. **Wrong secret**: Ensure the secret matches the one used to sign
2. **Expired token**: Check expiration time with `jwtDecode()`
3. **Malformed token**: Verify token has 3 parts separated by dots
4. **Clock skew**: Use `clockTolerance` option for synchronization issues

## 📄 License

MIT © [Adarsh Hatkar](https://github.com/AdarshHatkar)

## 🤝 Contributing

Contributions welcome! Please open an issue or submit a PR.

## 🔗 Links

- [GitHub](https://github.com/digicroz/jwt)
- [NPM](https://www.npmjs.com/package/@digicroz/jwt)
- [jsonwebtoken](https://github.com/auth0/node-jsonwebtoken)
