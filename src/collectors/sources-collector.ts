/**
 * @module sources-collector
 * Collects loaded text resources and extracts endpoints and comments.
 */

import { NetworkCapture } from '../browser/network-capture';
import { ElementsData } from './elements-collector';
import { CapturedSource, SourceMapInfo, ExtractedEndpoint, SuspiciousComment } from '../models/sources';
import { SUSPICIOUS_COMMENT_PATTERNS } from '../rules/keywords';
import { logger } from '../utils/logger';

export interface SourcesData {
  resources: CapturedSource[];
  sourceMaps: SourceMapInfo[];
  endpoints: ExtractedEndpoint[];
  suspiciousComments: SuspiciousComment[];
}

export class SourcesCollector {
  async collect(networkCapture: NetworkCapture, elementsData: ElementsData): Promise<SourcesData> {
    logger.info('Collecting Sources data...');

    const resources: CapturedSource[] = [];
    const sourceMaps: SourceMapInfo[] = [];
    const endpoints: ExtractedEndpoint[] = [];
    const suspiciousComments: SuspiciousComment[] = [];

    // 1. Process network text resources
    const networkEntries = networkCapture.getSuccessfulEntries();
    
    for (const entry of networkEntries) {
      const resp = entry.response;
      if (!resp || !resp.body) continue;

      const isJS = resp.contentType.includes('javascript') || resp.url.endsWith('.js');
      const isCSS = resp.contentType.includes('css') || resp.url.endsWith('.css');
      const isHTML = resp.contentType.includes('html');
      const isJSON = resp.contentType.includes('json');

      if (isJS || isCSS || isHTML || isJSON) {
        resources.push({
          url: resp.url,
          resourceType: entry.request.resourceType,
          status: resp.status,
          contentType: resp.contentType,
          size: resp.contentLength || resp.body.length,
          body: resp.body,
          bodyTruncated: resp.bodyTruncated,
          isInline: false,
        });

        // Source map extraction
        if (isJS || isCSS) {
          const smMatch = resp.body.match(/\/\/[#@]\s*sourceMappingURL=(.+?)(?:\s|$)/);
          if (smMatch) {
            sourceMaps.push({
              sourceMapUrl: smMatch[1],
              parentUrl: resp.url,
              originalSources: [],
              hasEmbeddedContent: false,
              accessible: false, // We don't actively fetch them yet to remain passive
            });
          }
        }

        // Endpoint and comment extraction for JS
        if (isJS) {
          this.extractEndpoints(resp.body, resp.url, endpoints);
          this.extractSuspiciousComments(resp.body, resp.url, suspiciousComments);
        }
      }
    }

    // 2. Process inline scripts from Elements
    elementsData.scripts.forEach((scriptBody, index) => {
      resources.push({
        url: `inline-script-${index}`,
        resourceType: 'script',
        status: 200,
        contentType: 'application/javascript',
        size: scriptBody.length,
        body: scriptBody,
        bodyTruncated: false,
        isInline: true,
        inlineIndex: index,
      });

      this.extractEndpoints(scriptBody, `inline-script-${index}`, endpoints);
      this.extractSuspiciousComments(scriptBody, `inline-script-${index}`, suspiciousComments);
    });

    logger.debug(`Collected ${resources.length} text resources, ${endpoints.length} endpoints, ${suspiciousComments.length} suspicious comments`);
    
    return {
      resources,
      sourceMaps,
      endpoints,
      suspiciousComments,
    };
  }

  private extractEndpoints(content: string, sourceUrl: string, endpoints: ExtractedEndpoint[]): void {
    // Basic endpoint extraction (fetch, XHR, axios, string literals starting with /api/)
    
    // Fetch/Axios/$.ajax calls
    const callPatterns = [
      /(?:fetch|axios|axios\.(?:get|post|put|delete|patch)|\$\.ajax|\$\.get|\$\.post)\s*\(\s*(['"`])(.*?)\1/g,
      /new\s+XMLHttpRequest\(\)\s*;\s*[^.]+\.open\(\s*['"`][A-Z]+['"`]\s*,\s*(['"`])(.*?)\1/g,
      /new\s+WebSocket\(\s*(['"`])(.*?)\1/g,
    ];

    for (const pattern of callPatterns) {
      let match;
      while ((match = pattern.exec(content)) !== null) {
        if (match[2] && match[2].length > 1) {
          endpoints.push({
            endpoint: match[2],
            extractionMethod: 'api_call',
            sourceUrl,
            location: `offset:${match.index}`,
          });
        }
      }
    }

    // Common endpoint string literals
    const literalPattern = /(['"`])(\/(?:api|graphql|v[1-9]|internal|admin|manage|secure)[\w\-/]+(?:\.[\w]+)?)\1/gi;
    let literalMatch;
    while ((literalMatch = literalPattern.exec(content)) !== null) {
      // Avoid duplicate captures if it was already caught by call patterns
      endpoints.push({
        endpoint: literalMatch[2],
        extractionMethod: 'string_literal',
        sourceUrl,
        location: `offset:${literalMatch.index}`,
      });
    }

    // Simple deduplication based on endpoint string
    const unique = new Map<string, ExtractedEndpoint>();
    endpoints.forEach(e => {
      // Just keep first occurrence for simplicity in collection
      if (!unique.has(e.endpoint)) {
        unique.set(e.endpoint, e);
      }
    });
    
    endpoints.length = 0;
    endpoints.push(...Array.from(unique.values()));
  }

  private extractSuspiciousComments(content: string, sourceUrl: string, comments: SuspiciousComment[]): void {
    // Extract single and multi-line comments
    const commentPatterns = [
      /\/\/\s*(.*?)(?:\n|$)/g,
      /\/\*\s*([\s\S]*?)\s*\*\//g
    ];

    for (const commentPattern of commentPatterns) {
      let match;
      while ((match = commentPattern.exec(content)) !== null) {
        const commentText = match[1];
        
        for (const rule of SUSPICIOUS_COMMENT_PATTERNS) {
          if (rule.pattern.test(commentText)) {
            comments.push({
              text: commentText.substring(0, 150) + (commentText.length > 150 ? '...' : ''), // Bounded size
              reason: rule.reason,
              sourceUrl,
              location: `offset:${match.index}`,
            });
            break; // One reason per comment is enough
          }
        }
      }
    }
  }
}
