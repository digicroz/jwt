type TSleepParams ={
    milliseconds?: number;
    seconds?: number;
    minutes?: number;
    until?: {
        unixTimestamp?: number;
    };
    random?:{
        milliseconds?: {
            min: number;
            max: number;
        }
        seconds?: {
            min: number;
            max: number;
        }
        minutes?: {
            min: number;
            max: number;
        }
    }
}

type TSleepReturn = Promise<void>;

/**
 * Sleep function that supports various delay options
 * @param params - Sleep parameters including fixed delays, random delays, or until timestamp
 * @returns Promise that resolves after the specified delay
 * @throws Error if invalid parameters are provided
 */
export const sleep = (params: TSleepParams): TSleepReturn => {
    return new Promise((resolve, reject) => {
        let delayMs = 0;

        try {
            // Validate input parameters
            if (!params || Object.keys(params).length === 0) {
                throw new Error('Sleep parameters cannot be empty');
            }

            // Handle sleeping until a specific timestamp
            if (params.until?.unixTimestamp) {
                const now = Date.now();
                const targetTime = params.until.unixTimestamp * 1000; // Convert to milliseconds
                delayMs = Math.max(0, targetTime - now);
                
                // If the timestamp is in the past, resolve immediately
                if (delayMs === 0) {
                    resolve();
                    return;
                }
            }
            // Handle random delays
            else if (params.random) {
                if (params.random.milliseconds) {
                    const { min, max } = params.random.milliseconds;
                    if (min < 0 || max < 0 || min > max) {
                        throw new Error('Invalid random milliseconds range');
                    }
                    delayMs = Math.random() * (max - min) + min;
                } else if (params.random.seconds) {
                    const { min, max } = params.random.seconds;
                    if (min < 0 || max < 0 || min > max) {
                        throw new Error('Invalid random seconds range');
                    }
                    delayMs = (Math.random() * (max - min) + min) * 1000;
                } else if (params.random.minutes) {
                    const { min, max } = params.random.minutes;
                    if (min < 0 || max < 0 || min > max) {
                        throw new Error('Invalid random minutes range');
                    }
                    delayMs = (Math.random() * (max - min) + min) * 60 * 1000;
                } else {
                    throw new Error('Random delay type must be specified (milliseconds, seconds, or minutes)');
                }
            }
            // Handle fixed delays
            else {
                if (params.milliseconds !== undefined) {
                    if (params.milliseconds < 0) {
                        throw new Error('Milliseconds cannot be negative');
                    }
                    delayMs += params.milliseconds;
                }
                if (params.seconds !== undefined) {
                    if (params.seconds < 0) {
                        throw new Error('Seconds cannot be negative');
                    }
                    delayMs += params.seconds * 1000;
                }
                if (params.minutes !== undefined) {
                    if (params.minutes < 0) {
                        throw new Error('Minutes cannot be negative');
                    }
                    delayMs += params.minutes * 60 * 1000;
                }

                // If no valid delay was specified
                if (delayMs === 0 && !params.milliseconds && !params.seconds && !params.minutes) {
                    throw new Error('At least one delay parameter must be specified');
                }
            }

            // Ensure delay is not too large (prevent potential issues)
            const MAX_DELAY = 2147483647; // Maximum value for setTimeout
            if (delayMs > MAX_DELAY) {
                throw new Error(`Delay too large. Maximum delay is ${MAX_DELAY}ms`);
            }

            setTimeout(resolve, Math.floor(delayMs));
        } catch (error) {
            reject(error);
        }
    });
};

/**
 * Convenience function to sleep for a specific number of milliseconds
 * @param ms - Number of milliseconds to sleep
 * @returns Promise that resolves after the specified delay
 */
export const sleepMs = (ms: number): TSleepReturn => {
    return sleep({ milliseconds: ms });
};

/**
 * Convenience function to sleep for a specific number of seconds
 * @param seconds - Number of seconds to sleep
 * @returns Promise that resolves after the specified delay
 */
export const sleepSeconds = (seconds: number): TSleepReturn => {
    return sleep({ seconds });
};

/**
 * Convenience function to sleep for a specific number of minutes
 * @param minutes - Number of minutes to sleep
 * @returns Promise that resolves after the specified delay
 */
export const sleepMinutes = (minutes: number): TSleepReturn => {
    return sleep({ minutes });
};

/**
 * Convenience function to sleep until a specific Unix timestamp
 * @param unixTimestamp - Unix timestamp (in seconds) to sleep until
 * @returns Promise that resolves at the specified timestamp
 */
export const sleepUntil = (unixTimestamp: number): TSleepReturn => {
    return sleep({ until: { unixTimestamp } });
};

// Export the type definitions for consumers
export type { TSleepParams, TSleepReturn };