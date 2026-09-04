/**
 * @module network
 * Network request/response models for captured traffic.
 */

/** Captured HTTP request information */
export interface CapturedRequest {
  /** Unique request identifier */
  id: string;
  /** Request URL */
  url: string;
  /** HTTP method */
  method: string;
  /** Resource type (document, script, xhr, fetch, etc.) */
  resourceType: string;
  /** Request initiator information */
  initiator?: string;
  /** Selected request headers */
  headers: Record<string, string>;
  /** Request timestamp */
  timestamp: string;
  /** Whether this request was for the main document */
  isNavigation: boolean;
  /** Post data if available and text-based */
  postData?: string;
}

/** Captured HTTP response information */
export interface CapturedResponse {
  /** Corresponding request ID */
  requestId: string;
  /** Response URL (may differ from request URL after redirect) */
  url: string;
  /** HTTP status code */
  status: number;
  /** HTTP status text */
  statusText: string;
  /** Content type header */
  contentType: string;
  /** Response headers */
  headers: Record<string, string>;
  /** Content length if known */
  contentLength: number | null;
  /** Response body (text only, bounded by max size) */
  body?: string;
  /** Whether body was truncated */
  bodyTruncated: boolean;
  /** Whether body capture failed */
  bodyCaptureFailed: boolean;
  /** Error message if body capture failed */
  bodyCaptureError?: string;
  /** Redirect chain for this request */
  redirectedFrom?: string;
  /** Response timing */
  timestamp: string;
}

/** Combined request/response pair */
export interface NetworkEntry {
  request: CapturedRequest;
  response?: CapturedResponse;
  /** Whether the request was aborted/failed */
  failed: boolean;
  /** Failure reason if applicable */
  failureReason?: string;
}

/** Security header analysis result */
export interface SecurityHeaderResult {
  /** Header name */
  header: string;
  /** Whether the header is present */
  present: boolean;
  /** Header value if present */
  value?: string;
  /** Assessment */
  assessment: 'good' | 'warning' | 'missing' | 'misconfigured';
  /** Description */
  description: string;
}
