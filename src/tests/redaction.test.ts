import { describe, it, expect, beforeEach } from 'vitest';
import { maskSensitiveValue, RedactionMode, setRedactionMode } from '../../src/utils/redaction';

describe('Redaction Utility', () => {
  beforeEach(() => {
    setRedactionMode(RedactionMode.SAFE); // reset to default
  });

  it('masks emails in SAFE mode', () => {
    expect(maskSensitiveValue('test.user@example.com', 'email')).toBe('t***@example.com');
  });

  it('masks emails in BALANCED mode', () => {
    setRedactionMode(RedactionMode.BALANCED);
    expect(maskSensitiveValue('test.user@example.com', 'email')).toBe('tes***@example.com');
  });

  it('masks credit cards in SAFE mode', () => {
    expect(maskSensitiveValue('4111 1111 1111 1111', 'credit_card')).toBe('************1111');
  });

  it('masks JWTs in SAFE mode', () => {
    expect(maskSensitiveValue('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz', 'jwt')).toBe('eyJ...REDACTED');
  });

  it('leaves data intact in FORENSIC mode except high risk', () => {
    setRedactionMode(RedactionMode.FORENSIC);
    expect(maskSensitiveValue('test.user@example.com', 'email')).toBe('test.user@example.com');
    expect(maskSensitiveValue('password123', 'password')).toBe('***REDACTED***'); // still redacted
  });
});
