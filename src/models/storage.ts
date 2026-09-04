/**
 * @module storage
 * Models for browser-side application state: cookies, storage, IndexedDB, caches, service workers.
 */

/** Captured cookie information */
export interface CapturedCookie {
  /** Cookie name */
  name: string;
  /** Cookie domain */
  domain: string;
  /** Cookie path */
  path: string;
  /** Whether Secure flag is set */
  secure: boolean;
  /** Whether HttpOnly flag is set */
  httpOnly: boolean;
  /** SameSite attribute */
  sameSite: 'Strict' | 'Lax' | 'None' | '';
  /** Expiration date (ISO string) or 'session' */
  expires: string;
  /** Masked cookie value */
  maskedValue: string;
  /** SHA-256 hash of value */
  valueHash: string;
  /** Size of value in bytes */
  valueSize: number;
  /** Whether this appears to be a session/auth cookie */
  isSessionLike: boolean;
  /** Security issues detected */
  securityIssues: string[];
}

/** Captured storage entry (localStorage or sessionStorage) */
export interface StorageEntry {
  /** Storage origin */
  origin: string;
  /** Storage key */
  key: string;
  /** Value type (string, json, etc.) */
  valueType: string;
  /** Size in bytes */
  size: number;
  /** Masked value */
  maskedValue: string;
  /** SHA-256 hash of value */
  valueHash: string;
  /** Sensitive data classification if detected */
  classification?: string;
  /** Raw value (only in forensic mode) */
  rawValue?: string;
}

/** Captured IndexedDB information */
export interface IndexedDBInfo {
  /** Database name */
  databaseName: string;
  /** Database version */
  version: number;
  /** Object stores */
  objectStores: IndexedDBStore[];
}

export interface IndexedDBStore {
  /** Object store name */
  name: string;
  /** Key path */
  keyPath: string | null;
  /** Whether auto-increment is enabled */
  autoIncrement: boolean;
  /** Index names */
  indexNames: string[];
  /** Sample records (bounded, cycle-safe) */
  sampleRecords: IndexedDBRecord[];
  /** Total record count if available */
  recordCount?: number;
}

export interface IndexedDBRecord {
  /** Record key */
  key: string;
  /** Serialized value (cycle-safe, bounded) */
  value: string;
  /** Size estimate */
  size: number;
}

/** Captured Cache Storage information */
export interface CacheStorageInfo {
  /** Cache name */
  cacheName: string;
  /** Cached request URLs */
  cachedUrls: string[];
  /** Inspected cached responses */
  inspectedResponses: CachedResponse[];
}

export interface CachedResponse {
  /** Request URL */
  url: string;
  /** Content type */
  contentType: string;
  /** Response status */
  status: number;
  /** Body content (text, bounded) */
  body?: string;
  /** Whether body was truncated */
  bodyTruncated: boolean;
}

/** Captured Service Worker information */
export interface ServiceWorkerInfo {
  /** Script URL */
  scriptUrl: string;
  /** Scope */
  scope: string;
  /** Registration state */
  state: string;
}

/** Complete application state collection */
export interface ApplicationState {
  cookies: CapturedCookie[];
  localStorage: StorageEntry[];
  sessionStorage: StorageEntry[];
  indexedDB: IndexedDBInfo[];
  cacheStorage: CacheStorageInfo[];
  serviceWorkers: ServiceWorkerInfo[];
}
