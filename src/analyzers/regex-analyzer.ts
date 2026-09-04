/**
 * @module regex-analyzer
 * Scans text for sensitive data using regular expressions.
 */

import { AnalysisMatch, DevToolsSurface } from '../models/findings';
import { REGEX_RULES } from '../rules/regex-rules';
import { ScanConfig } from '../config';
import { extractSnippetFromMatch } from '../utils/snippets';
import { maskSensitiveValue, ruleNameToSensitiveType } from '../utils/redaction';
import { normalizeByRule } from '../utils/normalization';

export class RegexAnalyzer {
  constructor(private config: ScanConfig) {}

  /**
   * Scan text against all regex rules.
   */
  scan(text: string, sourceIdentifier: string, sourceType: DevToolsSurface, url?: string): AnalysisMatch[] {
    if (!text || text.length === 0) return [];

    const matches: AnalysisMatch[] = [];
    const timestamp = new Date().toISOString();

    for (const rule of REGEX_RULES) {
      // Reset lastIndex for global regexes
      rule.pattern.lastIndex = 0;
      
      let match: RegExpExecArray | null;
      while ((match = rule.pattern.exec(text)) !== null) {
        // Use group 1 if present, otherwise full match
        const matchedStr = match[1] || match[0];
        
        // Apply rule-specific validation if available
        if (rule.validate && !rule.validate(matchedStr)) {
          continue;
        }

        const sensitiveType = ruleNameToSensitiveType(rule.name);
        const snippet = extractSnippetFromMatch(text, match, this.config.contextChars);

        matches.push({
          ruleName: rule.name,
          matchedValue: matchedStr,
          maskedValue: maskSensitiveValue(matchedStr, sensitiveType, this.config.redactionMode),
          normalizedValue: normalizeByRule(matchedStr, rule.name),
          sourceType,
          sourceIdentifier,
          url,
          location: `offset:${match.index}`,
          snippet,
          timestamp,
        });

        // Prevent infinite loops on poorly formed regexes
        if (match[0].length === 0) {
          rule.pattern.lastIndex++;
        }
      }
    }

    return matches;
  }
}
