/**
 * @module security-header-analyzer
 * Analyzes HTTP response headers for security misconfigurations.
 */

import { NetworkData } from '../collectors/network-collector';
import { SecurityHeaderResult } from '../models/network';
import { SECURITY_HEADER_RULES } from '../rules/security-rules';

export class SecurityHeaderAnalyzer {
  analyze(networkData: NetworkData, mainDocumentUrl: string): SecurityHeaderResult[] {
    const results: SecurityHeaderResult[] = [];
    
    // Find the main document response
    const mainEntry = networkData.entries.find(e => 
      e.request.isNavigation && 
      e.response && 
      e.response.url === mainDocumentUrl
    );

    if (!mainEntry || !mainEntry.response) {
      return results; // Cannot analyze if main document wasn't captured properly
    }

    const headers = mainEntry.response.headers;
    
    // Normalize header keys for case-insensitive lookup
    const normalizedHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(headers)) {
      normalizedHeaders[key.toLowerCase()] = value;
    }

    for (const rule of SECURITY_HEADER_RULES) {
      const headerLower = rule.header.toLowerCase();
      const value = normalizedHeaders[headerLower];
      const isPresent = value !== undefined;
      
      const assessment = rule.assess(value);

      results.push({
        header: rule.header,
        present: isPresent,
        value,
        assessment: assessment.assessment,
        description: assessment.detail,
      });
    }

    return results;
  }
}
