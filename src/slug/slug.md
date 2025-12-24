# Slug Utilities

URL-safe slug generation and validation utilities.

## Functions

### `isValidSlug(slug: string): boolean`

Checks if a string is a valid slug according to these rules:

- Contains only lowercase letters (a-z) and numbers (0-9)
- Hyphens (-) allowed between words only
- No consecutive hyphens
- No leading or trailing hyphens
- No other special characters or spaces

**Parameters:**

- `slug`: The string to validate

**Returns:** `boolean` - True if valid, false otherwise

**Examples:**

```typescript
import { isValidSlug } from "@digicroz/js-kit"

isValidSlug("hello-world") // true
isValidSlug("product-123") // true
isValidSlug("my-awesome-post") // true

isValidSlug("Hello-World") // false (uppercase)
isValidSlug("hello--world") // false (consecutive hyphens)
isValidSlug("-hello-world") // false (leading hyphen)
isValidSlug("hello-world-") // false (trailing hyphen)
isValidSlug("hello_world") // false (underscore)
isValidSlug("hello world") // false (space)
isValidSlug("hello@world") // false (special character)
```

---

### `convertToSlug(text: string, options?: { separator?: string }): string`

Converts any string to a URL-safe slug with the following transformations:

- Converts to lowercase
- Normalizes unicode characters (removes accents/diacritics)
- Replaces spaces and underscores with hyphens
- Removes all special characters
- Removes consecutive hyphens
- Trims leading and trailing hyphens

**Parameters:**

- `text`: The string to convert
- `options.separator`: (Optional) Character to use as separator, default is `'-'`

**Returns:** `string` - A URL-safe slug

**Examples:**

```typescript
import { convertToSlug } from "@digicroz/js-kit"

// Basic usage
convertToSlug("Hello World") // 'hello-world'
convertToSlug("The Quick Brown Fox") // 'the-quick-brown-fox'

// Handles multiple spaces and special characters
convertToSlug("Hello    World!!!") // 'hello-world'
convertToSlug("Product #123 - Special") // 'product-123-special'

// Removes accents and diacritics
convertToSlug("Café & Restaurant") // 'cafe-restaurant'
convertToSlug("Über Alles") // 'uber-alles'

// Handles underscores and other separators
convertToSlug("hello_world_test") // 'hello-world-test'
convertToSlug("hello---world") // 'hello-world'

// Trims whitespace
convertToSlug("  Hello World  ") // 'hello-world'

// Returns empty string for invalid input
convertToSlug("") // ''
convertToSlug("   ") // ''
```

---

### `generateUniqueSlug(baseSlug: string, existingSlugs: string[], options?: { separator?: string }): string`

Generates a unique slug by appending a number if the slug already exists in the provided array.

**Parameters:**

- `baseSlug`: The base slug to make unique
- `existingSlugs`: Array of existing slugs to check against
- `options.separator`: (Optional) Character to use before the number, default is `'-'`

**Returns:** `string` - A unique slug

**Examples:**

```typescript
import { generateUniqueSlug } from "@digicroz/js-kit"

// When slug doesn't exist
generateUniqueSlug("hello-world", []) // 'hello-world'
generateUniqueSlug("hello-world", ["other-slug"]) // 'hello-world'

// When slug exists
generateUniqueSlug("hello-world", ["hello-world"]) // 'hello-world-1'
generateUniqueSlug("hello-world", ["hello-world", "hello-world-1"]) // 'hello-world-2'

// Continues incrementing until unique
const existing = ["post", "post-1", "post-2", "post-3"]
generateUniqueSlug("post", existing) // 'post-4'
```

---

## Common Use Cases

### Creating a blog post slug

```typescript
import { convertToSlug, isValidSlug } from "@digicroz/js-kit"

const title = "My Awesome Blog Post!!!"
const slug = convertToSlug(title) // 'my-awesome-blog-post'

if (isValidSlug(slug)) {
  console.log("Slug is valid:", slug)
}
```

### Ensuring unique product slugs

```typescript
import { convertToSlug, generateUniqueSlug } from "@digicroz/js-kit"

const productName = "iPhone 15 Pro"
const baseSlug = convertToSlug(productName) // 'iphone-15-pro'

// Assume these slugs already exist in database
const existingSlugs = ["iphone-15-pro", "iphone-15-pro-1"]

const uniqueSlug = generateUniqueSlug(baseSlug, existingSlugs)
// Result: 'iphone-15-pro-2'
```

### Validating user input for custom URLs

```typescript
import { isValidSlug } from "@digicroz/js-kit"

function validateCustomUrl(userInput: string): boolean {
  if (!isValidSlug(userInput)) {
    throw new Error(
      "Invalid URL format. Use only lowercase letters, numbers, and hyphens."
    )
  }
  return true
}
```

### Handling international characters

```typescript
import { convertToSlug } from "@digicroz/js-kit"

convertToSlug("Crème Brûlée Recipe") // 'creme-brulee-recipe'
convertToSlug("São Paulo Travel Guide") // 'sao-paulo-travel-guide'
convertToSlug("München Sehenswürdigkeiten") // 'munchen-sehenswurdigkeiten'
```

---

## Best Practices

1. **Always validate user-provided slugs:**

   ```typescript
   if (!isValidSlug(userSlug)) {
     // Suggest conversion or show error
     const suggested = convertToSlug(userSlug)
   }
   ```

2. **Check for uniqueness in your database:**

   ```typescript
   async function createPost(title: string) {
     const baseSlug = convertToSlug(title)
     const existingSlugs = await db.posts.getAllSlugs()
     const uniqueSlug = generateUniqueSlug(baseSlug, existingSlugs)
     return db.posts.create({ title, slug: uniqueSlug })
   }
   ```

3. **Store slugs separately from titles:**

   - Don't regenerate slugs from titles on every request
   - Store the slug in your database for consistency
   - Update slugs only when explicitly needed (consider SEO impact)

4. **Consider slug length:**
   ```typescript
   const slug = convertToSlug(longTitle)
   const truncatedSlug = slug.substring(0, 50) // Keep reasonable length
   ```

---

## Zod Integration

The slug utilities work seamlessly with Zod for schema validation. Here are several approaches:

### Validation with Refine

Validate that a slug is in the correct format:

```typescript
import { z } from "zod"
import { isValidSlug } from "@digicroz/js-kit"

const postSchema = z.object({
  slug: z.string().refine(isValidSlug, {
    message:
      "Invalid slug format. Use lowercase, alphanumeric, and hyphens only.",
  }),
})

// ✓ Valid
postSchema.parse({ slug: "hello-world" })

// ✗ Throws error
postSchema.parse({ slug: "Hello World" })
```

### Auto-Transform to Slug

Automatically convert any string to a valid slug:

```typescript
import { z } from "zod"
import { convertToSlug } from "@digicroz/js-kit"

const postSchema = z.object({
  title: z.string(),
  slug: z.string().transform(convertToSlug),
})

const result = postSchema.parse({
  title: "My Awesome Post",
  slug: "My Awesome Post!!!",
})
// { title: 'My Awesome Post', slug: 'my-awesome-post' }
```

### Using Helper Functions

Use the provided Zod helper functions for cleaner code:

```typescript
import { z } from "zod"
import { zodSlugValidation, zodSlugTransform } from "@digicroz/js-kit"

// Validation
const validationSchema = z.object({
  slug: z.string().refine(zodSlugValidation(), {
    message: "Must be a valid slug",
  }),
})

// Transform
const transformSchema = z.object({
  slug: z.string().transform(zodSlugTransform()),
})
```

### Combined Validation and Transform

Validate user input OR auto-convert if needed:

```typescript
import { z } from "zod"
import { isValidSlug, convertToSlug } from "@digicroz/js-kit"

const postSchema = z
  .object({
    title: z.string().min(1, "Title is required"),
    customSlug: z.string().optional(),
    slug: z.string(),
  })
  .transform((data) => {
    // Use custom slug if provided and valid, otherwise generate from title
    const slug =
      data.customSlug && isValidSlug(data.customSlug)
        ? data.customSlug
        : convertToSlug(data.title)

    return { ...data, slug }
  })

// With valid custom slug
postSchema.parse({
  title: "My Post",
  customSlug: "my-custom-slug",
})
// { title: 'My Post', customSlug: 'my-custom-slug', slug: 'my-custom-slug' }

// Without custom slug, auto-generated
postSchema.parse({
  title: "My Awesome Post!",
})
// { title: 'My Awesome Post!', slug: 'my-awesome-post' }

// Invalid custom slug, auto-generated from title
postSchema.parse({
  title: "My Post",
  customSlug: "Invalid Slug!!!",
})
// { title: 'My Post', customSlug: 'Invalid Slug!!!', slug: 'my-post' }
```

### Real-World Example: Blog Post API

```typescript
import { z } from "zod"
import {
  isValidSlug,
  convertToSlug,
  generateUniqueSlug,
} from "@digicroz/js-kit"

// Request validation schema
const createPostSchema = z
  .object({
    title: z.string().min(1).max(200),
    content: z.string().min(1),
    slug: z.string().optional(),
    category: z.string(),
  })
  .transform((data) => ({
    ...data,
    slug:
      data.slug && isValidSlug(data.slug)
        ? data.slug
        : convertToSlug(data.title),
  }))

// Usage in API endpoint
async function createPost(input: unknown, db: Database) {
  // Validate and transform input
  const validated = createPostSchema.parse(input)

  // Ensure uniqueness
  const existingSlugs = await db.posts.getAllSlugs()
  const uniqueSlug = generateUniqueSlug(validated.slug, existingSlugs)

  // Save to database
  return db.posts.create({
    ...validated,
    slug: uniqueSlug,
  })
}

// Usage examples
await createPost(
  {
    title: "Getting Started with TypeScript",
    content: "...",
    category: "tutorials",
    // slug auto-generated: 'getting-started-with-typescript'
  },
  db
)

await createPost(
  {
    title: "My Post",
    content: "...",
    slug: "my-custom-slug",
    category: "blog",
    // Uses custom slug if valid
  },
  db
)
```

### Form Validation Example

```typescript
import { z } from "zod"
import { isValidSlug } from "@digicroz/js-kit"

const productFormSchema = z.object({
  name: z.string().min(1, "Product name is required"),
  slug: z
    .string()
    .min(1, "Slug is required")
    .refine(isValidSlug, {
      message: "Slug must contain only lowercase letters, numbers, and hyphens",
    })
    .refine(
      async (slug) => {
        // Check uniqueness in database
        const exists = await checkSlugExists(slug)
        return !exists
      },
      {
        message: "This slug is already taken",
      }
    ),
  price: z.number().positive(),
})

async function checkSlugExists(slug: string): Promise<boolean> {
  // Your database check logic
  return false
}
```

### E-commerce Category Schema

```typescript
import { z } from "zod"
import { convertToSlug, isValidSlug } from "@digicroz/js-kit"

const categorySchema = z
  .object({
    name: z.string().min(1).max(100),
    slug: z.string().optional(),
    parentId: z.string().uuid().nullable(),
    description: z.string().optional(),
  })
  .transform((data) => {
    // Auto-generate slug from name if not provided
    if (!data.slug || !isValidSlug(data.slug)) {
      return {
        ...data,
        slug: convertToSlug(data.name),
      }
    }
    return data
  })

// Usage
const category = categorySchema.parse({
  name: "Men's Clothing & Accessories",
  parentId: null,
})
// { name: "Men's Clothing & Accessories", slug: 'mens-clothing-accessories', parentId: null }
```

### Type-Safe with TypeScript

```typescript
import { z } from "zod"
import { isValidSlug, convertToSlug } from "@digicroz/js-kit"

const articleSchema = z.object({
  title: z.string(),
  slug: z.string().refine(isValidSlug),
})

type Article = z.infer<typeof articleSchema>

// TypeScript knows the shape
const article: Article = {
  title: "My Article",
  slug: "my-article", // Must be valid slug
}
```
