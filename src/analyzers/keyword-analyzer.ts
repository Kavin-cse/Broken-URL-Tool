/**
 * @module keyword-analyzer
 * Scans text for security-relevant keywords.
 */

import { AnalysisMatch, DevToolsSurface } from '../models/findings';
import { KEYWORD_DICTIONARY } from '../rules/keywords';
import { ScanConfig } from '../config';
import { extractSnippet } from '../utils/snippets';
import { normalizeWhitespace } from '../utils/normalization';

export class KeywordAnalyzer {
  constructor(private config: ScanConfig) {}

  /**
   * Scan text for all keywords in the dictionary.
   */
  scan(text: string, sourceIdentifier: string, sourceType: DevToolsSurface, url?: string): AnalysisMatch[] {
    if (!text || text.length === 0) return [];

    const matches: AnalysisMatch[] = [];
    // Normalize text once for case-insensitive scanning
    const lowerText = text.toLowerCase();
    const timestamp = new Date().toISOString();

    for (const entry of KEYWORD_DICTIONARY) {
      const keyword = entry.keyword.toLowerCase();
      let index = -1;
      
      // Find all occurrences
      while ((index = lowerText.indexOf(keyword, index + 1)) !== -1) {
        // Basic word boundary check to reduce false positives
        const isWordBoundaryBefore = index === 0 || !/[a-z0-9_]/i.test(lowerText[index - 1]);
        const isWordBoundaryAfter = index + keyword.length === lowerText.length || !/[a-z0-9_]/i.test(lowerText[index + keyword.length]);

        if (isWordBoundaryBefore && isWordBoundaryAfter) {
          const rawMatch = text.substring(index, index + keyword.length);
          const snippet = extractSnippet(text, index, index + keyword.length, this.config.contextChars);
          
          matches.push({
            ruleName: `keyword_${entry.category}`,
            matchedValue: rawMatch,
            maskedValue: rawMatch, // Keywords usually aren't secrets themselves, just indicators
            normalizedValue: normalizeWhitespace(rawMatch.toLowerCase()),
            sourceType,
            sourceIdentifier,
            url,
            location: `offset:${index}`,
            snippet,
            timestamp,
          });
        }
      }
    }

    return matches;
  }
}
