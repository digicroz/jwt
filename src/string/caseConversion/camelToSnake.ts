/* eslint-disable @typescript-eslint/no-explicit-any */
// camelCase → snake_case (string)
type CamelToSnake<S extends string> = S extends `${infer T}${infer U}`
  ? U extends Uncapitalize<U>
    ? `${Lowercase<T>}${CamelToSnake<U>}`
    : `${Lowercase<T>}_${CamelToSnake<U>}`
  : S

export type ToSnakeCaseResult<T extends string> = CamelToSnake<T>
// object keys
export type ObjectKeysToSnakeCaseResult<T> = {
  [K in keyof T as CamelToSnake<
    Extract<K, string>
  >]: T[K] extends readonly any[]
    ? ObjectKeysToSnakeCaseResult<T[K][number]>[]
    : T[K] extends object
    ? ObjectKeysToSnakeCaseResult<T[K]>
    : T[K]
}

/**
 * Converts a camelCase string to snake_case
 * Handles leading uppercase letters correctly
 *
 * @example
 * toSnakeCase('myVariable') // 'my_variable'
 * toSnakeCase('MyVariable') // 'my_variable'
 * toSnakeCase('XMLParser') // 'xml_parser'
 */
export const toSnakeCase = <T extends string>(
  value: T
): ToSnakeCaseResult<T> => {
  return value
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1_$2") // Handle consecutive caps like XMLParser
    .replace(/([a-z\d])([A-Z])/g, "$1_$2") // Handle normal camelCase
    .toLowerCase() as ToSnakeCaseResult<T>
}

/**
 * Converts all keys in an object from camelCase to snake_case recursively
 * Handles nested objects and arrays
 *
 * @example
 * objectKeysToSnakeCase({ firstName: 'John', userInfo: { phoneNumber: '123' } })
 * // { first_name: 'John', user_info: { phone_number: '123' } }
 */
export function objectKeysToSnakeCase<T extends Record<string, any>>(
  obj: T
): ObjectKeysToSnakeCaseResult<T> {
  if (obj === null || typeof obj !== "object") return obj as any

  if (Array.isArray(obj)) {
    return obj.map(objectKeysToSnakeCase) as any
  }

  return Object.keys(obj).reduce((acc, key) => {
    const snakeKey = toSnakeCase(key)
    acc[snakeKey] = objectKeysToSnakeCase(obj[key])
    return acc
  }, {} as any)
}
