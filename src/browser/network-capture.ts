/**
 * @module network-capture
 * Intercepts and captures all network requests/responses via Playwright events.
 */

import { Page, Request, Response } from 'playwright';
import { ScanConfig } from '../config';
import { CapturedRequest, CapturedResponse, NetworkEntry } from '../models/network';
import { logger } from '../utils/logger';
import { v4 as uuidv4 } from 'uuid';

/** Text-based content types that should have body captured */
const TEXT_CONTENT_TYPES = [
  'text/', 'application/json', 'application/javascript', 'application/xml',
  'application/xhtml+xml', 'application/ld+json', 'application/graphql',
  'application/x-www-form-urlencoded', 'image/svg+xml',
];

function isTextContentType(contentType: string): boolean {
  const lower = contentType.toLowerCase();
  return TEXT_CONTENT_TYPES.some(t => lower.includes(t));
}

export class NetworkCapture {
  private entries: Map<string, NetworkEntry> = new Map();
  private requestIdMap: Map<Request, string> = new Map();

  constructor(private config: ScanConfig) {}

  /**
   * Attach network capture listeners to a page.
   * Must be called before navigation.
   */
  attach(page: Page): void {
    page.on('request', (request: Request) => {
      this.handleRequest(request);
    });

    page.on('response', (response: Response) => {
      this.handleResponse(response).catch(err => {
        logger.debug(`Response capture error: ${err instanceof Error ? err.message : String(err)}`);
      });
    });

    page.on('requestfailed', (request: Request) => {
      this.handleFailedRequest(request);
    });

    logger.debug('Network capture attached');
  }

  private handleRequest(request: Request): void {
    const id = uuidv4();
    this.requestIdMap.set(request, id);

    const captured: CapturedRequest = {
      id,
      url: request.url(),
      method: request.method(),
      resourceType: request.resourceType(),
      headers: this.filterHeaders(request.headers()),
      timestamp: new Date().toISOString(),
      isNavigation: request.isNavigationRequest(),
      postData: request.postData() ?? undefined,
    };

    // Try to get initiator info
    try {
      const frame = request.frame();
      if (frame) {
        captured.initiator = frame.url();
      }
    } catch {
      // Initiator not available
    }

    this.entries.set(id, {
      request: captured,
      failed: false,
    });
  }

  private async handleResponse(response: Response): Promise<void> {
    const request = response.request();
    const id = this.requestIdMap.get(request);
    if (!id) return;

    const contentType = response.headers()['content-type'] || '';
    let body: string | undefined;
    let bodyTruncated = false;
    let bodyCaptureFailed = false;
    let bodyCaptureError: string | undefined;

    // Capture body for text-based responses
    if (isTextContentType(contentType)) {
      try {
        const buffer = await response.body();
        if (buffer.length > this.config.maxBodySize) {
          body = buffer.subarray(0, this.config.maxBodySize).toString('utf-8');
          bodyTruncated = true;
        } else {
          body = buffer.toString('utf-8');
        }
      } catch (err) {
        bodyCaptureFailed = true;
        bodyCaptureError = err instanceof Error ? err.message : String(err);
        logger.debug(`Body capture failed for ${response.url()}: ${bodyCaptureError}`);
      }
    }

    const captured: CapturedResponse = {
      requestId: id,
      url: response.url(),
      status: response.status(),
      statusText: response.statusText(),
      contentType,
      headers: response.headers(),
      contentLength: parseInt(response.headers()['content-length'] || '0', 10) || null,
      body,
      bodyTruncated,
      bodyCaptureFailed,
      bodyCaptureError,
      timestamp: new Date().toISOString(),
    };

    // Check for redirect source
    const redirectedFrom = request.redirectedFrom();
    if (redirectedFrom) {
      const fromId = this.requestIdMap.get(redirectedFrom);
      if (fromId) {
        captured.redirectedFrom = fromId;
      }
    }

    const entry = this.entries.get(id);
    if (entry) {
      entry.response = captured;
    }
  }

  private handleFailedRequest(request: Request): void {
    const id = this.requestIdMap.get(request);
    if (!id) return;

    const entry = this.entries.get(id);
    if (entry) {
      entry.failed = true;
      entry.failureReason = request.failure()?.errorText ?? 'Unknown failure';
    }
  }

  /**
   * Filter headers to keep only relevant ones (avoid storing sensitive auth headers in full).
   */
  private filterHeaders(headers: Record<string, string>): Record<string, string> {
    const relevant = [
      'content-type', 'content-length', 'cache-control', 'accept',
      'accept-language', 'referer', 'origin', 'host',
      'x-requested-with', 'x-forwarded-for',
    ];
    const filtered: Record<string, string> = {};
    for (const key of Object.keys(headers)) {
      const lower = key.toLowerCase();
      if (relevant.includes(lower)) {
        filtered[key] = headers[key];
      }
      // Record that authorization header exists but mask value
      if (lower === 'authorization') {
        filtered[key] = '[PRESENT - REDACTED]';
      }
      if (lower === 'cookie') {
        filtered[key] = '[PRESENT - REDACTED]';
      }
    }
    return filtered;
  }

  /**
   * Get all captured network entries.
   */
  getEntries(): NetworkEntry[] {
    return Array.from(this.entries.values());
  }

  /**
   * Get entries filtered by resource type.
   */
  getEntriesByType(...types: string[]): NetworkEntry[] {
    return this.getEntries().filter(e =>
      types.includes(e.request.resourceType)
    );
  }

  /**
   * Get entries with successful responses.
   */
  getSuccessfulEntries(): NetworkEntry[] {
    return this.getEntries().filter(e =>
      e.response && e.response.status >= 200 && e.response.status < 400
    );
  }
}
