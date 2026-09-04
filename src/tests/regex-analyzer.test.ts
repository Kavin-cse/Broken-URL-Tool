import { describe, it, expect } from 'vitest';
import { RegexAnalyzer } from '../../src/analyzers/regex-analyzer';
import { ScanConfig, DEFAULT_CONFIG } from '../../src/config';
import { DevToolsSurface } from '../../src/models/findings';

describe('RegexAnalyzer', () => {
  const config: ScanConfig = { ...DEFAULT_CONFIG };
  const analyzer = new RegexAnalyzer(config);
  const surface = DevToolsSurface.SOURCES;
  const sourceId = 'test.js';

  it('detects emails', () => {
    const text = 'Contact us at test.user@example.com for more info.';
    const matches = analyzer.scan(text, sourceId, surface);
    const emailMatch = matches.find(m => m.ruleName === 'email');
    expect(emailMatch).toBeDefined();
    expect(emailMatch?.matchedValue).toBe('test.user@example.com');
  });

  it('detects US phone numbers', () => {
    const text = 'Call 555-019-8372 for support.';
    const matches = analyzer.scan(text, sourceId, surface);
    const phoneMatch = matches.find(m => m.ruleName === 'us_phone');
    expect(phoneMatch).toBeDefined();
    expect(phoneMatch?.matchedValue).toBe('555-019-8372');
  });

  it('detects SSNs (and respects area validation)', () => {
    const valid = 'My SSN is 123-45-6789.';
    const invalid = 'Fake SSN 000-12-3456.'; // 000 area is invalid
    
    let matches = analyzer.scan(valid, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'us_ssn')).toBeDefined();

    matches = analyzer.scan(invalid, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'us_ssn')).toBeUndefined();
  });

  it('detects credit cards and validates with Luhn', () => {
    // 4242424242424242 is a valid test card, let's use a simpler one passing luhn
    // 4111111111111111 passes luhn
    const valid = 'Card: 4111-1111-1111-1111';
    const invalid = 'Card: 4111-1111-1111-1112'; // fails luhn
    
    let matches = analyzer.scan(valid, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'credit_card')).toBeDefined();

    matches = analyzer.scan(invalid, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'credit_card')).toBeUndefined();
  });

  it('detects JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const matches = analyzer.scan(`Bearer ${jwt}`, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'jwt')).toBeDefined();
  });

  it('detects AWS access keys', () => {
    const text = 'AWS_KEY = AKIAIOSFODNN7EXAMPLE';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'aws_access_key')).toBeDefined();
  });

  it('detects private keys', () => {
    const text = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'private_key')).toBeDefined();
  });

  it('detects internal IPv4 addresses', () => {
    const text = 'DB_HOST=10.0.1.45';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'internal_ipv4')).toBeDefined();
  });

  it('detects DB connection strings', () => {
    const text = 'mongodb://user:pass@localhost:27017/test';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'mongodb_connection')).toBeDefined();
  });

  it('detects UUIDs', () => {
    const text = 'ID: 123e4567-e89b-12d3-a456-426614174000';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.ruleName === 'uuid')).toBeDefined();
  });

  it('detects API keys in URL parameters', () => {
    const text = 'https://api.example.com/data?api_key=sk_live_1234567890abcdef';
    const matches = analyzer.scan(text, sourceId, surface);
    const match = matches.find(m => m.ruleName === 'api_key_param');
    expect(match).toBeDefined();
    expect(match?.matchedValue).toBe('sk_live_1234567890abcdef'); // Group 1 should be captured
  });
});
