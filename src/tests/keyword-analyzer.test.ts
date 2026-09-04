import { describe, it, expect } from 'vitest';
import { KeywordAnalyzer } from '../../src/analyzers/keyword-analyzer';
import { ScanConfig, DEFAULT_CONFIG } from '../../src/config';
import { DevToolsSurface } from '../../src/models/findings';

describe('KeywordAnalyzer', () => {
  const config: ScanConfig = { ...DEFAULT_CONFIG, contextChars: 10 };
  const analyzer = new KeywordAnalyzer(config);
  const surface = DevToolsSurface.SOURCES;
  const sourceId = 'test.js';

  it('scans for keywords and respects word boundaries', () => {
    // "password" should match, "passwords" should not because of word boundary check
    // Wait, the word boundary check checks if next char is [a-z0-9_]. 's' is in that, so it won't match "password" inside "passwords".
    // That is the intended behavior (exact word match). Let's verify.
    const text = 'Enter your password here, not passwords.';
    const matches = analyzer.scan(text, sourceId, surface);
    
    const pwdMatches = matches.filter(m => m.ruleName === 'keyword_credentials' && m.matchedValue.toLowerCase() === 'password');
    expect(pwdMatches.length).toBe(1); // Should only find "password", not the prefix of "passwords"
  });

  it('is case-insensitive', () => {
    const text = 'This is TOP SECRET info.';
    const matches = analyzer.scan(text, sourceId, surface);
    expect(matches.find(m => m.matchedValue.toLowerCase() === 'top secret')).toBeDefined();
  });

  it('extracts snippets', () => {
    const text = 'The database password is very secure.';
    const matches = analyzer.scan(text, sourceId, surface);
    const match = matches.find(m => m.matchedValue.toLowerCase() === 'password');
    expect(match?.snippet).toContain('database password is very');
  });
});
