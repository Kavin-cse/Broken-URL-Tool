/**
 * @module config
 * Central configuration for DevInspect Security Auditor.
 */

import { RedactionMode } from './utils/redaction';

export interface ScanConfig {
  /** Target URL to audit */
  targetUrl: string;
  /** Run browser in headless mode */
  headless: boolean;
  /** Navigation timeout in milliseconds */
  timeout: number;
  /** Network idle timeout in milliseconds */
  networkIdleTimeout: number;
  /** Additional wait time after page load (stabilization delay) */
  waitMs: number;
  /** Output file path for JSON report */
  outputPath: string;
  /** Output file path for HTML report */
  htmlPath: string;
  /** Maximum response body size to capture (bytes) */
  maxBodySize: number;
  /** Context snippet size (characters before and after match) */
  contextChars: number;
  /** Redaction mode */
  redactionMode: RedactionMode;
  /** Verbose logging */
  verbose: boolean;
  /** Ignore HTTPS errors */
  ignoreHttpsErrors: boolean;
  /** Custom user agent */
  userAgent?: string;
  /** Maximum number of console messages to capture */
  maxConsoleMessages: number;
  /** Maximum number of IndexedDB records per store to inspect */
  maxIndexedDBRecords: number;
  /** Maximum number of cache entries to inspect */
  maxCacheEntries: number;
}

/** Default configuration values */
export const DEFAULT_CONFIG: ScanConfig = {
  targetUrl: '',
  headless: true,
  timeout: 30000,
  networkIdleTimeout: 5000,
  waitMs: 2000,
  outputPath: 'exposure_report.json',
  htmlPath: 'exposure_report.html',
  maxBodySize: 5 * 1024 * 1024, // 5MB
  contextChars: 30,
  redactionMode: RedactionMode.SAFE,
  verbose: false,
  ignoreHttpsErrors: false,
  maxConsoleMessages: 1000,
  maxIndexedDBRecords: 100,
  maxCacheEntries: 200,
};
