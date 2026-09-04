/**
 * @module sources
 * Models for collected text-based browser resources.
 */

/** A captured source resource */
export interface CapturedSource {
  /** Source URL */
  url: string;
  /** Resource type (script, stylesheet, document, etc.) */
  resourceType: string;
  /** HTTP status code */
  status: number;
  /** Content type */
  contentType: string;
  /** Size in bytes */
  size: number;
  /** Body content (text only, bounded) */
  body?: string;
  /** Whether body was truncated */
  bodyTruncated: boolean;
  /** Whether this is an inline script */
  isInline: boolean;
  /** Inline script index if applicable */
  inlineIndex?: number;
}

/** Source map information */
export interface SourceMapInfo {
  /** Source map URL */
  sourceMapUrl: string;
  /** Parent script URL */
  parentUrl: string;
  /** Original source file names */
  originalSources: string[];
  /** Whether source content is embedded */
  hasEmbeddedContent: boolean;
  /** Whether the source map was successfully fetched */
  accessible: boolean;
}

/** An endpoint extracted from JavaScript source code */
export interface ExtractedEndpoint {
  /** The endpoint path or URL */
  endpoint: string;
  /** How it was extracted (fetch, XMLHttpRequest, axios, string literal, etc.) */
  extractionMethod: string;
  /** Source file URL */
  sourceUrl: string;
  /** Location within the source (line/offset) */
  location?: string;
  /** Context snippet */
  snippet?: string;
}

/** A suspicious comment found in source code */
export interface SuspiciousComment {
  /** The comment text */
  text: string;
  /** Why it was flagged */
  reason: string;
  /** Source file URL */
  sourceUrl: string;
  /** Location within the source */
  location?: string;
  /** Context snippet */
  snippet?: string;
}

/** Captured console message */
export interface CapturedConsoleMessage {
  /** Message level (log, info, warn, error, debug) */
  level: string;
  /** Message text */
  text: string;
  /** Timestamp */
  timestamp: string;
  /** Source location (file:line:col) */
  sourceLocation?: string;
  /** Serializable arguments */
  args?: string[];
}

/** Captured page error */
export interface CapturedPageError {
  /** Error message */
  message: string;
  /** Stack trace */
  stack?: string;
  /** Timestamp */
  timestamp: string;
}
