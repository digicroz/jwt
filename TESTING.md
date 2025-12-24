# Testing Guide for @digicroz/js-kit

## Test Framework: Vitest

We use [Vitest](https://vitest.dev/) for testing - a blazing fast unit test framework powered by Vite.

## Running Tests

### Available Commands

```bash
# Run tests once
npm test

# Run tests in watch mode (incremental testing)
npm run test:watch

# Run tests with UI interface
npm run test:ui

# Run tests with coverage report
npm run test:coverage

# Run tests with coverage in watch mode
npm run test:coverage:watch
```

## Incremental Testing (Watch Mode)

**Watch mode is the recommended way to develop** - it provides instant feedback as you write code:

```bash
npm run test:watch
```

Features:
- 🔥 **Hot Module Replacement (HMR)** - Tests re-run instantly on file changes
- 🎯 **Smart filtering** - Press `p` to filter by filename, `t` to filter by test name
- ⚡ **Only changed files** - By default, only re-runs tests related to changed files
- 🔍 **Interactive mode** - Navigate and control tests from the terminal

### Watch Mode Shortcuts

When running `npm run test:watch`:
- Press `a` to run all tests
- Press `f` to run only failed tests
- Press `p` to filter by filename pattern
- Press `t` to filter by test name pattern
- Press `c` to clear console
- Press `q` to quit

## Test Structure

### Directory Layout (Co-located Tests)

Tests live next to the code they test for better maintainability:

```
src/
  ├── array/
  │   ├── index.ts
  │   └── index.test.ts       ← Test file
  ├── string/
  │   ├── capitalize.ts
  │   ├── capitalize.test.ts  ← Test file
  │   ├── truncate.ts
  │   ├── index.ts
  │   └── ...
  ├── number/
  │   ├── index.ts
  │   └── index.test.ts
  └── slug/
      ├── index.ts
      └── index.test.ts
```

**Benefits:**
- ✅ Tests live with the code - easier to maintain
- ✅ Simpler imports: `import { fn } from './index'`
- ✅ Better visibility - see tests when browsing code
- ✅ Modern standard - used by Vite, Vitest, React projects

### Writing Tests

Example test structure:

```typescript
import { describe, it, expect } from 'vitest';
import { yourFunction } from './index'; // Simple relative import

describe('your module', () => {
  describe('yourFunction', () => {
    it('should do something', () => {
      const result = yourFunction('input');
      expect(result).toBe('expected');
    });

    it('should handle edge cases', () => {
      expect(() => yourFunction(null)).toThrow('error message');
    });
  });
});
```

## Coverage Reports

Generate coverage reports to ensure code quality:

```bash
npm run test:coverage
```

This generates:
- **Console output** - Quick summary in terminal
- **HTML report** - Detailed report in `coverage/` directory
- **LCOV format** - For CI/CD integration

### Coverage Thresholds

Current thresholds (configured in `vitest.config.ts`):
- Lines: 80%
- Functions: 80%
- Branches: 75%
- Statements: 80%

## Best Practices

### 1. Test Organization
- Group related tests using `describe` blocks
- Use descriptive test names that explain the behavior
- One assertion per test when possible

### 2. Test Coverage
- Test happy paths
- Test edge cases (empty inputs, null, undefined)
- Test error conditions
- Test type validation

### 3. Incremental Development
1. Write a failing test
2. Implement the minimum code to pass
3. Refactor while keeping tests green
4. Run in watch mode for instant feedback

### 4. Test Naming Convention
```typescript
describe('module name', () => {
  describe('function name', () => {
    it('should describe expected behavior', () => {
      // test code
    });
  });
});
```

## CI/CD Integration

Add to your GitHub Actions workflow:

```yaml
- name: Run Tests
  run: npm test

- name: Generate Coverage
  run: npm run test:coverage

- name: Upload Coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage/lcov.info
```

## Debugging Tests

### VS Code Integration
1. Install "Vitest" extension
2. Click the ▶️ icon next to any test to run/debug it
3. Set breakpoints in your test or source files

### Console Debugging
Add `console.log()` in your tests - output appears in watch mode immediately.

## Common Patterns

### Testing Async Functions
```typescript
it('should handle async operations', async () => {
  const result = await asyncFunction();
  expect(result).toBe('expected');
});
```

### Testing Errors
```typescript
it('should throw error for invalid input', () => {
  expect(() => functionThatThrows()).toThrow('error message');
});
```

### Testing Type Guards
```typescript
it('should validate types correctly', () => {
  expect(isValidType(validInput)).toBe(true);
  expect(isValidType(invalidInput)).toBe(false);
});
```

## Tips for Maximum Productivity

1. **Keep watch mode running** while developing
2. **Use test-driven development (TDD)** - write tests first
3. **Focus on one test at a time** - use `.only` modifier
4. **Skip slow tests temporarily** - use `.skip` modifier
5. **Use UI mode** for visual test exploration: `npm run test:ui`

## Resources

- [Vitest Documentation](https://vitest.dev/)
- [Vitest API Reference](https://vitest.dev/api/)
- [Testing Best Practices](https://vitest.dev/guide/test-patterns)
