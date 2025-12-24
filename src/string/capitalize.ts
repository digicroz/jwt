/**
 * Capitalizes the first letter of a string
 * @param str - The string to capitalize
 * @returns The capitalized string
 */
export function capitalize(str: string): string {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }
  
  if (str.length === 0) {
    return str;
  }
  
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Capitalizes the first letter of each word in a string
 * @param str - The string to capitalize
 * @returns The string with each word capitalized
 */
export function capitalizeWords(str: string): string {
  if (typeof str !== 'string') {
    throw new Error('Input must be a string');
  }
  
  return str.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function convertCamelToNormalCapitalized(
    camelCaseString: string
): string {
    // Split the camelCase string into words
    const words = camelCaseString
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .split(/[\s_]+/);

    // Capitalize each word
    const capitalizedWords = words.map(
        (word) => word.charAt(0).toUpperCase() + word.slice(1)
    );

    // Join the capitalized words to form the normal capitalized string
    const normalCapitalizedString = capitalizedWords.join(" ");

    return normalCapitalizedString;
}