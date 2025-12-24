/* eslint-disable @typescript-eslint/no-explicit-any */
// Convert snake_case string to camelCase
type SnakeToCamel<S extends string> = S extends `${infer T}_${infer U}`
  ? `${T}${Capitalize<SnakeToCamel<U>>}`
  : S

export type ToCamelCaseResult<T extends string> = SnakeToCamel<T>

// Convert object keys recursively
export type ObjectKeysToCamelCaseResult<T> = {
  [K in keyof T as SnakeToCamel<
    Extract<K, string>
  >]: T[K] extends readonly any[]
    ? ObjectKeysToCamelCaseResult<T[K][number]>[]
    : T[K] extends object
    ? ObjectKeysToCamelCaseResult<T[K]>
    : T[K]
}

/**
 * Converts a snake_case string to camelCase
 *
 * @example
 * toCamelCase('my_variable') // 'myVariable'
 * toCamelCase('user_first_name') // 'userFirstName'
 */
export const toCamelCase = <T extends string>(str: T): ToCamelCaseResult<T> => {
  return str.replace(/_([a-z])/g, (_, char) =>
    char.toUpperCase()
  ) as ToCamelCaseResult<T>
}

/**
 * Converts all keys in an object from snake_case to camelCase recursively
 * Handles nested objects and arrays
 *
 * @example
 * objectKeysToCamelCase({ first_name: 'John', user_info: { phone_number: '123' } })
 * // { firstName: 'John', userInfo: { phoneNumber: '123' } }
 */
export function objectKeysToCamelCase<T extends Record<string, any>>(
  obj: T
): ObjectKeysToCamelCaseResult<T> {
  if (obj === null || typeof obj !== "object") return obj as any

  if (Array.isArray(obj)) {
    return obj.map(objectKeysToCamelCase) as any
  }

  return Object.keys(obj).reduce((acc, key) => {
    const camelKey = toCamelCase(key)
    acc[camelKey] = objectKeysToCamelCase(obj[key])
    return acc
  }, {} as any)
}
