# Array Utilities

Powerful array manipulation utilities for JavaScript/TypeScript applications.

## Features

- ✅ **Full TypeScript Support** - Complete type definitions and generic support
- ✅ **Comprehensive JSDoc** - Detailed documentation for all functions
- ✅ **Error Handling** - Robust input validation and error messages
- ✅ **Generic Types** - Type-safe array operations with generics
- ✅ **Performance Optimized** - Efficient algorithms for array operations
- ✅ **Zero Dependencies** - Pure JavaScript implementations

## Installation

```bash
npm install @digicroz/js-kit
```

## Usage

### Two Usage Patterns

You can use the array utilities in two ways:

#### 1. Individual Function Imports (Recommended)

```typescript
import { chunk } from "@digicroz/js-kit/array"

const result = chunk([1, 2, 3, 4, 5], 2)
// Result: [[1, 2], [3, 4], [5]]
```

#### 2. Package Import

```typescript
import { chunk } from "@digicroz/js-kit"

const result = chunk([1, 2, 3, 4, 5], 2)
// Result: [[1, 2], [3, 4], [5]]
```

### Basic Array Operations

```typescript
import { chunk } from "@digicroz/js-kit/array"

// Split an array into chunks
const numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
const chunks = chunk(numbers, 3)
console.log(chunks)
// Output: [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10]]

// Working with different data types
const strings = ["a", "b", "c", "d", "e"]
const stringChunks = chunk(strings, 2)
console.log(stringChunks)
// Output: [['a', 'b'], ['c', 'd'], ['e']]

// Working with objects
interface User {
  id: number
  name: string
}

const users: User[] = [
  { id: 1, name: "Alice" },
  { id: 2, name: "Bob" },
  { id: 3, name: "Charlie" },
  { id: 4, name: "David" },
]

const userChunks = chunk(users, 2)
console.log(userChunks)
// Output: [[{id: 1, name: 'Alice'}, {id: 2, name: 'Bob'}], [{id: 3, name: 'Charlie'}, {id: 4, name: 'David'}]]
```

### Advanced Usage

```typescript
import { chunk } from "@digicroz/js-kit/array"

// Processing large datasets in chunks
const processInBatches = async <T>(
  items: T[],
  batchSize: number,
  processor: (batch: T[]) => Promise<void>
) => {
  const batches = chunk(items, batchSize)

  for (const batch of batches) {
    await processor(batch)
    console.log(`Processed batch of ${batch.length} items`)
  }
}

// Example usage
const largeDataset = Array.from({ length: 1000 }, (_, i) => i + 1)

await processInBatches(largeDataset, 50, async (batch) => {
  // Process each batch of 50 items
  console.log(`Processing items ${batch[0]} to ${batch[batch.length - 1]}`)
  await new Promise((resolve) => setTimeout(resolve, 100)) // Simulate async work
})

// Pagination helper
const createPagination = <T>(items: T[], itemsPerPage: number) => {
  const pages = chunk(items, itemsPerPage)

  return {
    pages,
    totalPages: pages.length,
    totalItems: items.length,
    getPage: (pageNumber: number) => pages[pageNumber - 1] || [],
    hasPage: (pageNumber: number) =>
      pageNumber >= 1 && pageNumber <= pages.length,
  }
}

// Example usage
const allItems = Array.from({ length: 25 }, (_, i) => `Item ${i + 1}`)
const pagination = createPagination(allItems, 5)

console.log(`Total pages: ${pagination.totalPages}`)
console.log(`Page 1:`, pagination.getPage(1))
console.log(`Page 3:`, pagination.getPage(3))
```

### Error Handling

```typescript
import { chunk } from "@digicroz/js-kit/array"

try {
  // This will throw an error
  chunk([1, 2, 3], 0)
} catch (error) {
  console.error(error.message) // "Chunk size must be greater than 0"
}

try {
  // This will throw an error
  chunk([1, 2, 3], -1)
} catch (error) {
  console.error(error.message) // "Chunk size must be greater than 0"
}

// Safe chunking with validation
const safeChunk = <T>(array: T[], size: number): T[][] => {
  if (!Array.isArray(array)) {
    throw new Error("First argument must be an array")
  }

  if (!Number.isInteger(size) || size <= 0) {
    throw new Error("Chunk size must be a positive integer")
  }

  return chunk(array, size)
}
```

## API Reference

### `chunk<T>(array: T[], size: number): T[][]`

Splits an array into chunks of a specified size.

**Parameters:**

- `array` - The array to split into chunks
- `size` - The size of each chunk (must be greater than 0)

**Returns:** `T[][]` - An array of chunks

**Throws:** `Error` when:

- `size` is less than or equal to 0
- `size` is not a number

**Time Complexity:** O(n) where n is the length of the input array
**Space Complexity:** O(n) for the output array

### Type Definitions

```typescript
// The chunk function is generic and works with any type
function chunk<T>(array: T[], size: number): T[][]

// Example type usage
const numbers: number[] = [1, 2, 3, 4, 5]
const numberChunks: number[][] = chunk(numbers, 2)

const strings: string[] = ["a", "b", "c"]
const stringChunks: string[][] = chunk(strings, 2)

interface CustomObject {
  id: string
  value: number
}
const objects: CustomObject[] = [
  /* ... */
]
const objectChunks: CustomObject[][] = chunk(objects, 3)
```

## Best Practices

1. **Choose appropriate chunk sizes**: Consider memory usage and processing capabilities
2. **Validate inputs**: Always validate array and chunk size parameters in production code
3. **Handle edge cases**: Consider empty arrays and arrays smaller than chunk size
4. **Use for batch processing**: Ideal for processing large datasets in manageable batches
5. **Consider memory usage**: Large chunks may consume significant memory

## Common Use Cases

### Batch API Requests

```typescript
import { chunk } from "@digicroz/js-kit/array"

const batchApiRequests = async (ids: string[], batchSize: number = 10) => {
  const batches = chunk(ids, batchSize)
  const results = []

  for (const batch of batches) {
    const batchResults = await Promise.all(
      batch.map((id) => fetch(`/api/items/${id}`).then((r) => r.json()))
    )
    results.push(...batchResults)

    // Add delay between batches to respect rate limits
    await new Promise((resolve) => setTimeout(resolve, 100))
  }

  return results
}
```

### Grid Layout Data

```typescript
import { chunk } from "@digicroz/js-kit/array"

const createGridData = <T>(items: T[], columns: number) => {
  return chunk(items, columns)
}

// For a 3-column grid
const gridItems = ["A", "B", "C", "D", "E", "F", "G"]
const gridRows = createGridData(gridItems, 3)
// Result: [['A', 'B', 'C'], ['D', 'E', 'F'], ['G']]
```

### Progress Tracking

```typescript
import { chunk } from "@digicroz/js-kit/array"

const processWithProgress = async <T>(
  items: T[],
  batchSize: number,
  processor: (item: T) => Promise<void>
) => {
  const batches = chunk(items, batchSize)
  let processed = 0

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]

    await Promise.all(batch.map(processor))

    processed += batch.length
    const progress = (processed / items.length) * 100

    console.log(
      `Progress: ${progress.toFixed(1)}% (${processed}/${items.length})`
    )
  }
}
```

## Performance Considerations

- **Memory Usage**: The function creates a new array structure. For very large arrays, consider streaming approaches
- **Time Complexity**: O(n) linear time complexity
- **Immutable**: Original array is not modified, new chunks are created
- **No Dependencies**: Pure JavaScript implementation with no external dependencies

## License

This module is part of the @digicroz/js-kit package.
