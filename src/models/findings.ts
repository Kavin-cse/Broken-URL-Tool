/**
 * @module findings
 * Core finding model for DevInspect Security Auditor.
 * Every security observation is represented as a Finding.
 */

/** Severity levels for findings */
export enum Severity {
  INFO = 'INFO',
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
  CRITICAL = 'CRITICAL',
}

/** Confidence levels for findings */
export enum Confidence {
  LOW = 'LOW',
  MEDIUM = 'MEDIUM',
  HIGH = 'HIGH',
}

/** Categories of security findings */
export enum FindingCategory {
  SENSITIVE_DATA_EXPOSURE = 'Sensitive Data Exposure',
  AUTHENTICATION_STATE_EXPOSURE = 'Authentication State Exposure',
  AUTHORIZATION_INDICATOR = 'Authorization Indicator',
  CLIENT_SIDE_SECRET = 'Client-Side Secret',
  API_EXPOSURE = 'API Exposure',
  SESSION_SECURITY = 'Session Security',
  SECURITY_CONFIGURATION = 'Security Configuration',
  DEBUG_INFORMATION = 'Debug Information',
  INTERNAL_INFRASTRUCTURE = 'Internal Infrastructure Exposure',
  PII_EXPOSURE = 'PII Exposure',
  CREDENTIAL_EXPOSURE = 'Credential Exposure',
}

/** DevTools surfaces that can provide evidence */
export enum DevToolsSurface {
  ELEMENTS = 'Elements',
  SOURCES = 'Sources',
  NETWORK = 'Network',
  APPLICATION = 'Application',
  CONSOLE = 'Console',
}

/** A single piece of evidence supporting a finding */
export interface Evidence {
  /** Which DevTools surface this evidence comes from */
  surface: DevToolsSurface;
  /** Type of evidence (e.g., 'keyword_match', 'regex_match', 'cookie', 'header') */
  type: string;
  /** Human-readable description */
  description: string;
  /** The source URL or identifier */
  source: string;
  /** Location within the source (selector, line number, key path) */
  location?: string;
  /** Matched value (masked) */
  maskedValue?: string;
  /** Context snippet around the match */
  snippet?: string;
  /** Raw value (only populated in FORENSIC mode) */
  rawValue?: string;
  /** Timestamp of observation */
  timestamp?: string;
}

/** A security finding produced by the auditor */
export interface Finding {
  /** Unique identifier */
  id: string;
  /** Short descriptive title */
  title: string;
  /** Category classification */
  category: FindingCategory;
  /** Severity level */
  severity: Severity;
  /** Confidence level */
  confidence: Confidence;
  /** Detailed description */
  description: string;
  /** Potential impact */
  impact: string;
  /** Recommended remediation */
  remediation: string;
  /** Evidence supporting this finding */
  evidence: Evidence[];
  /** DevTools surfaces that contributed evidence */
  sources: DevToolsSurface[];
  /** Statistical counts (e.g., { emails: 5, tokens: 2 }) */
  counts: Record<string, number>;
  /** Timestamps */
  timestamps: {
    firstSeen: string;
    lastSeen: string;
  };
}

/** A match from keyword or regex analysis */
export interface AnalysisMatch {
  /** Rule name that matched */
  ruleName: string;
  /** The matched value */
  matchedValue: string;
  /** Masked version of the matched value */
  maskedValue: string;
  /** Normalized version for deduplication */
  normalizedValue: string;
  /** Source type (elements, sources, network, application, console) */
  sourceType: DevToolsSurface;
  /** Source identifier (URL, selector, key name) */
  sourceIdentifier: string;
  /** URL context */
  url?: string;
  /** Location/offset within source */
  location?: string;
  /** Context snippet */
  snippet?: string;
  /** Timestamp */
  timestamp: string;
}

/** Deduplicated match group */
export interface MatchGroup {
  /** Rule name */
  ruleName: string;
  /** Total match count */
  totalCount: number;
  /** Unique match count */
  uniqueCount: number;
  /** First 10 unique samples (masked) */
  samples: AnalysisMatch[];
  /** Context snippets (up to 5) */
  snippets: string[];
}

/** The complete scan result */
export interface ScanResult {
  /** Scan metadata */
  metadata: ScanMetadata;
  /** Navigation information */
  navigation: NavigationInfo;
  /** Collected data from each surface */
  collections: {
    elements: ElementsData;
    sources: SourcesData;
    network: NetworkData;
    application: ApplicationData;
    console: ConsoleData;
  };
  /** All findings */
  findings: Finding[];
  /** Summary statistics */
  summary: ScanSummary;
  /** Warnings encountered during scan */
  warnings: string[];
  /** Scan configuration used */
  config: Record<string, unknown>;
}

export interface ScanMetadata {
  toolName: string;
  toolVersion: string;
  targetUrl: string;
  scanStartTime: string;
  scanEndTime: string;
  scanDurationMs: number;
}

export interface NavigationInfo {
  requestedUrl: string;
  finalUrl: string;
  statusCode: number | null;
  statusText: string;
  pageTitle: string;
  redirectChain: RedirectInfo[];
  navigationSuccessful: boolean;
}

export interface RedirectInfo {
  url: string;
  status: number;
  statusText: string;
}

// Forward-declared data types - actual shapes defined in their modules
export type ElementsData = Record<string, unknown>;
export type SourcesData = Record<string, unknown>;
export type NetworkData = Record<string, unknown>;
export type ApplicationData = Record<string, unknown>;
export type ConsoleData = Record<string, unknown>;

export interface ScanSummary {
  totalFindings: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  bySurface: Record<string, number>;
  surfaceStatus: Record<string, boolean>;
  uniqueMatchesByRule: Record<string, number>;
}
