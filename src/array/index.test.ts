import { describe, it, expect } from 'vitest';
import { chunk } from './index';

describe('array utilities', () => {
  describe('chunk', () => {
    it('should split array into chunks of specified size', () => {
      const input = [1, 2, 3, 4, 5, 6, 7, 8];
      const result = chunk(input, 3);
      expect(result).toEqual([[1, 2, 3], [4, 5, 6], [7, 8]]);
    });

    it('should handle exact division', () => {
      const input = [1, 2, 3, 4];
      const result = chunk(input, 2);
      expect(result).toEqual([[1, 2], [3, 4]]);
    });

    it('should return empty array for empty input', () => {
      const result = chunk([], 3);
      expect(result).toEqual([]);
    });

    it('should handle chunk size larger than array', () => {
      const input = [1, 2, 3];
      const result = chunk(input, 5);
      expect(result).toEqual([[1, 2, 3]]);
    });

    it('should throw error for invalid chunk size', () => {
      expect(() => chunk([1, 2, 3], 0)).toThrow('Chunk size must be greater than 0');
      expect(() => chunk([1, 2, 3], -1)).toThrow('Chunk size must be greater than 0');
    });

    it('should work with different data types', () => {
      const strings = ['a', 'b', 'c', 'd', 'e'];
      const result = chunk(strings, 2);
      expect(result).toEqual([['a', 'b'], ['c', 'd'], ['e']]);
    });

    it('should work with objects', () => {
      const objects = [{ id: 1 }, { id: 2 }, { id: 3 }];
      const result = chunk(objects, 2);
      expect(result).toEqual([[{ id: 1 }, { id: 2 }], [{ id: 3 }]]);
    });
  });
});
