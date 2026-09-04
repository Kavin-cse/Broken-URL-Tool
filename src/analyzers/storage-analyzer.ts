/**
 * @module storage-analyzer
 * Analyzes Application state (storage/cookies) for sensitive data keys.
 */

import { ApplicationState } from '../models/storage';
import { SENSITIVE_STORAGE_PATTERNS } from '../rules/security-rules';

export class StorageAnalyzer {
  analyze(appState: ApplicationState): void {
    // Classify local storage keys
    for (const entry of appState.localStorage) {
      this.classifyStorageEntry(entry);
    }

    // Classify session storage keys
    for (const entry of appState.sessionStorage) {
      this.classifyStorageEntry(entry);
    }
  }

  private classifyStorageEntry(entry: { key: string; classification?: string }): void {
    for (const rule of SENSITIVE_STORAGE_PATTERNS) {
      if (rule.pattern.test(entry.key)) {
        entry.classification = rule.classification;
        break;
      }
    }
  }
}
