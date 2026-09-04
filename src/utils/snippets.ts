/**
 * @module snippets
 * Context snippet extraction around matches.
 */

const DEFAULT_CONTEXT_CHARS = 30;

/**
 * Extract a context snippet around a match position.
 * @param text - The full text
 * @param matchStart - Start index of the match
 * @param matchEnd - End index of the match
 * @param contextChars - Number of context characters before and after
 * @returns Formatted snippet with ellipsis markers
 */
export function extractSnippet(
  text: string,
  matchStart: number,
  matchEnd: number,
  contextChars: number = DEFAULT_CONTEXT_CHARS
): string {
  if (!text || matchStart < 0 || matchEnd < 0) return '';

  const safeStart = Math.max(0, matchStart - contextChars);
  const safeEnd = Math.min(text.length, matchEnd + contextChars);

  const before = text.substring(safeStart, matchStart);
  const match = text.substring(matchStart, matchEnd);
  const after = text.substring(matchEnd, safeEnd);

  const prefix = safeStart > 0 ? '...' : '';
  const suffix = safeEnd < text.length ? '...' : '';

  // Clean up whitespace (newlines, tabs -> spaces)
  const clean = (s: string) => s.replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ');

  return `${prefix}${clean(before)}${clean(match)}${clean(after)}${suffix}`;
}

/**
 * Extract a snippet around a regex match within text.
 * @param text - The full text
 * @param match - The regex match
 * @param contextChars - Number of context characters
 * @returns Formatted snippet
 */
export function extractSnippetFromMatch(
  text: string,
  match: RegExpExecArray,
  contextChars: number = DEFAULT_CONTEXT_CHARS
): string {
  const matchStart = match.index;
  const matchEnd = matchStart + match[0].length;
  return extractSnippet(text, matchStart, matchEnd, contextChars);
}

/**
 * Truncate a string to a maximum length, adding ellipsis if truncated.
 * @param text - The text to truncate
 * @param maxLength - Maximum length
 * @returns Truncated text
 */
export function truncate(text: string, maxLength: number = 200): string {
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return text.substring(0, maxLength - 3) + '...';
}

/**
 * Sanitize text for safe display (remove control chars, limit length).
 */
export function sanitizeForDisplay(text: string, maxLength: number = 500): string {
  if (!text) return '';
  // Remove control characters except newline and tab
  // eslint-disable-next-line no-control-regex
  const cleaned = text.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
  return truncate(cleaned, maxLength);
}
