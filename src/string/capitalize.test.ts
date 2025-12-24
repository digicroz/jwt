import { describe, it, expect } from 'vitest';
import { capitalize, capitalizeWords, convertCamelToNormalCapitalized } from './capitalize';

describe('string/capitalize', () => {
  describe('capitalize', () => {
    it('should capitalize first letter of lowercase string', () => {
      expect(capitalize('hello')).toBe('Hello');
    });

    it('should not change already capitalized string', () => {
      expect(capitalize('World')).toBe('World');
    });

    it('should handle single character', () => {
      expect(capitalize('a')).toBe('A');
    });

    it('should return empty string for empty input', () => {
      expect(capitalize('')).toBe('');
    });

    it('should handle strings with spaces', () => {
      expect(capitalize('hello world')).toBe('Hello world');
    });

    it('should throw error for non-string input', () => {
      expect(() => capitalize(123 as any)).toThrow('Input must be a string');
      expect(() => capitalize(null as any)).toThrow('Input must be a string');
    });
  });

  describe('capitalizeWords', () => {
    it('should capitalize first letter of each word', () => {
      expect(capitalizeWords('hello world')).toBe('Hello World');
    });

    it('should handle single word', () => {
      expect(capitalizeWords('hello')).toBe('Hello');
    });

    it('should handle multiple spaces', () => {
      expect(capitalizeWords('hello  world')).toBe('Hello  World');
    });

    it('should handle punctuation', () => {
      expect(capitalizeWords('hello, world!')).toBe('Hello, World!');
    });

    it('should return empty string for empty input', () => {
      expect(capitalizeWords('')).toBe('');
    });

    it('should throw error for non-string input', () => {
      expect(() => capitalizeWords(123 as any)).toThrow('Input must be a string');
    });
  });

  describe('convertCamelToNormalCapitalized', () => {
    it('should convert camelCase to Normal Capitalized', () => {
      expect(convertCamelToNormalCapitalized('helloWorld')).toBe('Hello World');
    });

    it('should handle single word', () => {
      expect(convertCamelToNormalCapitalized('hello')).toBe('Hello');
    });

    it('should handle multiple capital letters', () => {
      expect(convertCamelToNormalCapitalized('thisIsATest')).toBe('This Is ATest');
    });

    it('should handle underscores', () => {
      expect(convertCamelToNormalCapitalized('hello_world')).toBe('Hello World');
    });

    it('should handle mixed case and underscores', () => {
      expect(convertCamelToNormalCapitalized('helloWorld_test')).toBe('Hello World Test');
    });
  });
});
