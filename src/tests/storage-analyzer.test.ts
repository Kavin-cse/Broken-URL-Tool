import { describe, it, expect } from 'vitest';
import { StorageAnalyzer } from '../../src/analyzers/storage-analyzer';
import { ApplicationState } from '../../src/models/storage';

describe('StorageAnalyzer', () => {
  const analyzer = new StorageAnalyzer();

  it('classifies sensitive storage keys', () => {
    const appState: ApplicationState = {
      cookies: [],
      localStorage: [
        { origin: 'test', key: 'auth_token', valueType: 'string', size: 10, maskedValue: '...', valueHash: '' },
        { origin: 'test', key: 'theme', valueType: 'string', size: 4, maskedValue: 'dark', valueHash: '' },
      ],
      sessionStorage: [
        { origin: 'test', key: 'user_role', valueType: 'string', size: 5, maskedValue: 'admin', valueHash: '' }
      ],
      indexedDB: [],
      cacheStorage: [],
      serviceWorkers: [],
    };

    analyzer.analyze(appState);

    expect(appState.localStorage[0].classification).toBe('auth_token');
    expect(appState.localStorage[1].classification).toBeUndefined();
    expect(appState.sessionStorage[0].classification).toBe('role');
  });
});
