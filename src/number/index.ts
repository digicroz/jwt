/**
 * Clamps a number within the inclusive lower and upper bounds
 * @param number - The number to clamp
 * @param lower - The lower bound
 * @param upper - The upper bound
 * @returns The clamped number
 */
export function clamp(number: number, lower: number, upper: number): number {
  if (typeof number !== 'number' || typeof lower !== 'number' || typeof upper !== 'number') {
    throw new Error('All arguments must be numbers');
  }
  
  if (lower > upper) {
    throw new Error('Lower bound must be less than or equal to upper bound');
  }
  
  return Math.min(Math.max(number, lower), upper);
}

/**
 * Checks if a number is within the inclusive range
 * @param number - The number to check
 * @param lower - The lower bound
 * @param upper - The upper bound
 * @returns True if the number is within the range
 */
export function inRange(number: number, lower: number, upper: number): boolean {
  if (typeof number !== 'number' || typeof lower !== 'number' || typeof upper !== 'number') {
    throw new Error('All arguments must be numbers');
  }
  
  if (lower > upper) {
    throw new Error('Lower bound must be less than or equal to upper bound');
  }
  
  return number >= lower && number <= upper;
}


export const convertToInt = (data: any): number => {
    if (isNaN(data)) {
        throw new Error('Invalid input: not a number');
    }
    if (data === null || data === undefined) {
        throw new Error('Invalid input: null or undefined');
    }

    if (typeof data === 'number') {
        data = data + '';
    }

    return +parseInt(data);
};

export const convertToTwoDecimalInt = (data: any): number => {
    if (isNaN(data)) {
        throw new Error('Invalid input: not a number');
    }
    if (data === null || data === undefined) {
        throw new Error('Invalid input: null or undefined');
    }

    if (typeof data === 'number') {
        data = data + '';
    }
    return +parseFloat(data).toFixed(2);
};

export const randomNumberWithFixedLength = (length: number): number => {
    if (length <= 0 || !Number.isInteger(length)) {
        throw new Error('Length must be a positive integer.');
    }
    return Math.floor(
        Math.pow(10, length - 1) +
        Math.random() * (9 * Math.pow(10, length - 1))
    );
};
