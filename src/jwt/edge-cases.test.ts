import { describe, it, expect } from 'vitest';
import * as jwt from 'jsonwebtoken';
import { jwtDecode, jwtVerify } from './index';
import { JwtErrorType } from '../types/jwt.types';

describe('JWT Edge Cases', () => {
  it('should handle tokens with non-object payloads (string)', () => {
    // Create a token with a string payload using raw jsonwebtoken
    // jwtSign in this library prevents this, but external tokens might have it
    const secret = 'test-secret';
    const token = jwt.sign(JSON.stringify('string-payload'), secret);

    // Try to decode it
    // Default generic is JwtPayload which is an object
    const result = jwtDecode(token);

    // We expect this to fail because we want to enforce object payloads
    // consistent with jwtSign
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN);
      expect(result.error.message).toContain('Payload must be an object');
    }
  });

  it('should handle tokens with non-object payloads (verify)', async () => {
    const secret = 'test-secret';
    const token = jwt.sign(JSON.stringify('string-payload'), secret);

    const result = await jwtVerify(token, secret);

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.type).toBe(JwtErrorType.INVALID_TOKEN);
      expect(result.error.message).toContain('Payload must be an object');
    }
  });
});
