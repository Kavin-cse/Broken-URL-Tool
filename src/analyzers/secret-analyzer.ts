/**
 * @module secret-analyzer
 * Facade combining keyword and regex analyzers.
 */

import { ScanConfig } from '../config';
import { AnalysisMatch, DevToolsSurface, MatchGroup } from '../models/findings';
import { KeywordAnalyzer } from './keyword-analyzer';
import { RegexAnalyzer } from './regex-analyzer';

export class SecretAnalyzer {
  private keywordAnalyzer: KeywordAnalyzer;
  private regexAnalyzer: RegexAnalyzer;

  constructor(config: ScanConfig) {
    this.keywordAnalyzer = new KeywordAnalyzer(config);
    this.regexAnalyzer = new RegexAnalyzer(config);
  }

  /**
   * Scan text using both keyword and regex analyzers.
   */
  scan(text: string, sourceIdentifier: string, sourceType: DevToolsSurface, url?: string): AnalysisMatch[] {
    const keywordMatches = this.keywordAnalyzer.scan(text, sourceIdentifier, sourceType, url);
    const regexMatches = this.regexAnalyzer.scan(text, sourceIdentifier, sourceType, url);
    return [...keywordMatches, ...regexMatches];
  }

  /**
   * Group and deduplicate matches by rule name and normalized value.
   */
  static groupMatches(matches: AnalysisMatch[]): MatchGroup[] {
    const groups = new Map<string, MatchGroup>();

    for (const match of matches) {
      if (!groups.has(match.ruleName)) {
        groups.set(match.ruleName, {
          ruleName: match.ruleName,
          totalCount: 0,
          uniqueCount: 0,
          samples: [],
          snippets: [],
        });
      }

      const group = groups.get(match.ruleName)!;
      group.totalCount++;

      // Check if this is a unique value in this group
      const isUnique = !group.samples.some(s => s.normalizedValue === match.normalizedValue);
      
      if (isUnique) {
        group.uniqueCount++;
        // Keep up to 10 unique samples
        if (group.samples.length < 10) {
          group.samples.push(match);
        }
      }

      // Collect unique snippets (up to 5)
      if (match.snippet && group.snippets.length < 5) {
        if (!group.snippets.includes(match.snippet)) {
          group.snippets.push(match.snippet);
        }
      }
    }

    return Array.from(groups.values());
  }
}
