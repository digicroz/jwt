/**
 * Helper function for enum filtering
 * Checks if a search value exists in an enum array and returns it with proper typing
 * @param enumArray - Array of enum values to search in
 * @param searchValue - Value to search for
 * @returns The typed enum value if found, undefined otherwise
 * @example
 * ```ts
 * const Status = ['active', 'inactive', 'pending'] as const;
 * const result = parseEnumValue(Status, 'active'); // 'active'
 * const invalid = parseEnumValue(Status, 'unknown'); // undefined
 * ```
 */
export const parseEnumValue = <T extends readonly string[]>(
  enumArray: T,
  value: string
): T[number] | undefined => {
  return enumArray.includes(value as T[number])
    ? (value as T[number])
    : undefined
}

export const requireEnumValue = <T extends readonly string[]>(
  enumArray: T,
  value: string
): T[number] => {
  if (!enumArray.includes(value as T[number])) {
    throw new Error(`Invalid enum value: ${value}`)
  }
  return value as T[number]
}
