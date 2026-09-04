/**
 * @module network-collector
 * Collects and formats network capture data for analysis.
 */

import { NetworkCapture } from '../browser/network-capture';
import { NetworkEntry } from '../models/network';
import { logger } from '../utils/logger';

export interface NetworkData {
  entries: NetworkEntry[];
  summary: {
    totalRequests: number;
    successfulRequests: number;
    failedRequests: number;
    byResourceType: Record<string, number>;
    byStatusCode: Record<string, number>;
  };
}

export class NetworkCollector {
  collect(networkCapture: NetworkCapture): NetworkData {
    logger.info('Collecting Network data...');

    const entries = networkCapture.getEntries();
    
    const summary = {
      totalRequests: entries.length,
      successfulRequests: entries.filter(e => e.response && e.response.status >= 200 && e.response.status < 400).length,
      failedRequests: entries.filter(e => e.failed || (e.response && e.response.status >= 400)).length,
      byResourceType: {} as Record<string, number>,
      byStatusCode: {} as Record<string, number>,
    };

    for (const entry of entries) {
      // Aggregate resource types
      const type = entry.request.resourceType;
      summary.byResourceType[type] = (summary.byResourceType[type] || 0) + 1;

      // Aggregate status codes
      if (entry.response) {
        const status = entry.response.status.toString();
        summary.byStatusCode[status] = (summary.byStatusCode[status] || 0) + 1;
      } else if (entry.failed) {
        summary.byStatusCode['failed'] = (summary.byStatusCode['failed'] || 0) + 1;
      }
    }

    logger.debug(`Collected ${entries.length} network requests`);

    return {
      entries,
      summary,
    };
  }
}
