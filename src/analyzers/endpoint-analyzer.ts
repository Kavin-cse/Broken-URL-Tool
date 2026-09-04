/**
 * @module endpoint-analyzer
 * Analyzes discovered endpoints for security significance.
 */

import { SourcesData } from '../collectors/sources-collector';
import { NetworkData } from '../collectors/network-collector';
import { ROUTE_INDICATORS } from '../rules/keywords';
import { normalizeUrl } from '../utils/normalization';

export interface AnalyzedEndpoint {
  url: string;
  sourceType: 'source_code' | 'network_traffic';
  sourceUrl?: string;
  classification: string[];
  status?: number;
  contentType?: string;
  isApi: boolean;
  isSuspicious: boolean;
  snippet?: string;
}

export class EndpointAnalyzer {
  analyze(sources: SourcesData, network: NetworkData): AnalyzedEndpoint[] {
    const endpointsMap = new Map<string, AnalyzedEndpoint>();

    // 1. Process endpoints from Source Code
    for (const ep of sources.endpoints) {
      // Very naive URL resolution (assume relative if starts with /, else ignore if not http)
      let resolvedUrl = ep.endpoint;
      if (resolvedUrl.startsWith('/')) {
        // We'd ideally need the base URL here, but for analysis we can just use the path
      } else if (!resolvedUrl.startsWith('http')) {
        continue; // Skip non-URL looking things
      }

      const normalized = normalizeUrl(resolvedUrl);
      const classification = this.classifyEndpoint(normalized);

      endpointsMap.set(normalized, {
        url: ep.endpoint,
        sourceType: 'source_code',
        sourceUrl: ep.sourceUrl,
        classification,
        isApi: classification.includes('api'),
        isSuspicious: classification.length > 0 && !classification.includes('api'), // APIs are common, others are suspicious
        snippet: ep.snippet,
      });
    }

    // 2. Process endpoints actually called in Network Traffic
    for (const entry of network.entries) {
      if (entry.request.resourceType === 'fetch' || entry.request.resourceType === 'xhr') {
        const normalized = normalizeUrl(entry.request.url);
        const classification = this.classifyEndpoint(normalized);
        
        let existing = endpointsMap.get(normalized);
        if (existing) {
          // Update existing with network info
          existing.status = entry.response?.status;
          existing.contentType = entry.response?.contentType;
        } else {
          endpointsMap.set(normalized, {
            url: entry.request.url,
            sourceType: 'network_traffic',
            classification,
            status: entry.response?.status,
            contentType: entry.response?.contentType,
            isApi: classification.includes('api'),
            isSuspicious: classification.length > 0 && !classification.includes('api'),
          });
        }
      }
    }

    return Array.from(endpointsMap.values());
  }

  private classifyEndpoint(url: string): string[] {
    const classification: string[] = [];
    const urlLower = url.toLowerCase();

    for (const route of ROUTE_INDICATORS) {
      if (urlLower.includes(route.pattern)) {
        classification.push(route.category);
      }
    }

    return Array.from(new Set(classification));
  }
}
