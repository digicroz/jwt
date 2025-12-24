/**
 * Checks if a string is a valid slug
 * A valid slug contains only lowercase alphanumeric characters and hyphens,
 * with no consecutive hyphens and no leading/trailing hyphens
 * 
 * @param slug - The string to validate
 * @returns True if the string is a valid slug, false otherwise
 * 
 * @example
 * ```ts
 * isValidSlug('hello-world') // true
 * isValidSlug('hello--world') // false (consecutive hyphens)
 * isValidSlug('Hello-World') // false (uppercase)
 * isValidSlug('-hello-world') // false (leading hyphen)
 * isValidSlug('hello_world') // false (underscore not allowed)
 * ```
 */
export function isValidSlug(slug: string): boolean {
  if (!slug || typeof slug !== 'string') {
    return false;
  }

  // Check if slug matches the pattern:
  // - starts with alphanumeric
  // - ends with alphanumeric
  // - contains only lowercase alphanumeric and single hyphens
  const slugPattern = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
  
  return slugPattern.test(slug);
}

/**
 * Converts a string to a URL-safe slug
 * - Converts to lowercase
 * - Removes special characters
 * - Replaces spaces and underscores with hyphens
 * - Removes consecutive hyphens
 * - Trims leading and trailing hyphens
 * 
 * @param text - The string to convert to a slug
 * @param options - Optional configuration
 * @param options.separator - Character to use as separator (default: '-')
 * @returns A URL-safe slug
 * 
 * @example
 * ```ts
 * convertToSlug('Hello World') // 'hello-world'
 * convertToSlug('Hello  World!!!') // 'hello-world'
 * convertToSlug('Hello_World') // 'hello-world'
 * convertToSlug('  Hello World  ') // 'hello-world'
 * convertToSlug('Hello---World') // 'hello-world'
 * convertToSlug('Café & Restaurant') // 'cafe-restaurant'
 * convertToSlug('Product #123') // 'product-123'
 * ```
 */
export function convertToSlug(
  text: string,
  options: { separator?: string } = {}
): string {
  const { separator = '-' } = options;

  if (!text || typeof text !== 'string') {
    return '';
  }

  return text
    .toString()
    .toLowerCase()
    .trim()
    // Remove accents and diacritics
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    // Replace spaces, underscores, and other common separators with separator
    .replace(/[\s_]+/g, separator)
    // Remove all non-alphanumeric characters except the separator
    .replace(new RegExp(`[^a-z0-9${separator}]`, 'g'), '')
    // Replace multiple consecutive separators with single separator
    .replace(new RegExp(`${separator}+`, 'g'), separator)
    // Remove leading and trailing separators
    .replace(new RegExp(`^${separator}+|${separator}+$`, 'g'), '');
}

/**
 * Generates a unique slug by appending a number if the slug already exists
 * 
 * @param baseSlug - The base slug to make unique
 * @param existingSlugs - Array of existing slugs to check against
 * @param options - Optional configuration
 * @param options.separator - Character to use before the number (default: '-')
 * @returns A unique slug
 * 
 * @example
 * ```ts
 * generateUniqueSlug('hello-world', ['hello-world']) // 'hello-world-1'
 * generateUniqueSlug('hello-world', ['hello-world', 'hello-world-1']) // 'hello-world-2'
 * generateUniqueSlug('hello-world', []) // 'hello-world'
 * ```
 */
export function generateUniqueSlug(
  baseSlug: string,
  existingSlugs: string[],
  options: { separator?: string } = {}
): string {
  const { separator = '-' } = options;

  if (!existingSlugs.includes(baseSlug)) {
    return baseSlug;
  }

  let counter = 1;
  let uniqueSlug = `${baseSlug}${separator}${counter}`;

  while (existingSlugs.includes(uniqueSlug)) {
    counter++;
    uniqueSlug = `${baseSlug}${separator}${counter}`;
  }

  return uniqueSlug;
}

/**
 * Creates a Zod refinement function for slug validation
 * Use with z.string().refine() or z.string().superRefine()
 * 
 * @param message - Custom error message (optional)
 * @returns Refinement function for Zod
 * 
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { zodSlugValidation } from '@digicroz/js-kit';
 * 
 * const schema = z.object({
 *   slug: z.string().refine(zodSlugValidation(), {
 *     message: 'Invalid slug format'
 *   })
 * });
 * ```
 */
export function zodSlugValidation(message?: string) {
  return (val: string) => isValidSlug(val);
}

/**
 * Creates a Zod transform function that converts strings to slugs
 * Use with z.string().transform()
 * 
 * @param options - Optional configuration
 * @param options.separator - Character to use as separator (default: '-')
 * @returns Transform function for Zod
 * 
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { zodSlugTransform } from '@digicroz/js-kit';
 * 
 * const schema = z.object({
 *   title: z.string(),
 *   slug: z.string().transform(zodSlugTransform())
 * });
 * 
 * schema.parse({ title: 'Hello', slug: 'Hello World!!!' })
 * // { title: 'Hello', slug: 'hello-world' }
 * ```
 */
export function zodSlugTransform(options?: { separator?: string }) {
  return (val: string) => convertToSlug(val, options);
}

/**
 * Pre-configured Zod schema for slug validation
 * Validates that the string is a valid slug format
 * 
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { slugSchema } from '@digicroz/js-kit';
 * 
 * const postSchema = z.object({
 *   slug: slugSchema
 * });
 * 
 * postSchema.parse({ slug: 'hello-world' }); // ✓ Valid
 * postSchema.parse({ slug: 'Hello World' }); // ✗ Invalid
 * ```
 */
export const slugSchema = {
  /**
   * Get a Zod string schema that validates slug format
   * Requires zod to be installed: npm install zod
   */
  create: (customMessage?: string) => {
    // Dynamic import to avoid making zod a required dependency
    return {
      _type: 'slug-validator' as const,
      validate: zodSlugValidation(customMessage),
      message: customMessage || 'Must be a valid slug (lowercase, alphanumeric, and hyphens only, no consecutive hyphens)'
    };
  }
};

/**
 * Pre-configured Zod schema that auto-converts strings to slugs
 * Automatically transforms any string input into a valid slug
 * 
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { autoSlugSchema } from '@digicroz/js-kit';
 * 
 * const postSchema = z.object({
 *   title: z.string(),
 *   slug: z.string().transform(autoSlugSchema.transform())
 * });
 * 
 * postSchema.parse({ title: 'My Post', slug: 'Hello World!!!' })
 * // { title: 'My Post', slug: 'hello-world' }
 * ```
 */
export const autoSlugSchema = {
  /**
   * Get a transform function for Zod
   */
  transform: (options?: { separator?: string }) => zodSlugTransform(options)
};
