import { describe, it, expect } from 'vitest';
import { extractSnippet, truncate } from '../../src/utils/snippets';

describe('Snippets Utility', () => {
  it('extracts snippet around match', () => {
    const text = 'This is a long string containing a secret_key right here.';
    // "secret_key" is at index 35
    const matchStart = 35;
    const matchEnd = 45;
    
    // With 10 chars context
    const snippet = extractSnippet(text, matchStart, matchEnd, 10);
    expect(snippet).toBe('...ntaining a secret_key right here.');
  });

  it('handles matches near start or end', () => {
    const text = 'secret is hidden';
    expect(extractSnippet(text, 0, 6, 5)).toBe('secret is hi...');
    expect(extractSnippet(text, 10, 16, 5)).toBe('...s hidden');
  });

  it('truncates long text properly', () => {
    const text = 'a'.repeat(300);
    expect(truncate(text, 100).length).toBe(100);
    expect(truncate(text, 100).endsWith('...')).toBe(true);
  });
});
