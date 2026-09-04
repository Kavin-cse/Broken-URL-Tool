/**
 * @module correlation-engine
 * Correlates evidence across all 5 DevTools surfaces to produce cohesive findings.
 */

import { Finding, FindingCategory, Severity, Confidence, Evidence, DevToolsSurface, MatchGroup } from '../models/findings';
import { AuthIndicators } from '../analyzers/auth-analyzer';
import { AnalyzedEndpoint } from '../analyzers/endpoint-analyzer';
import { SecurityHeaderResult } from '../models/network';
import { ApplicationState, CapturedCookie } from '../models/storage';
import { v4 as uuidv4 } from 'uuid';

export class CorrelationEngine {
  correlate(
    secretMatches: MatchGroup[],
    authIndicators: AuthIndicators,
    endpoints: AnalyzedEndpoint[],
    securityHeaders: SecurityHeaderResult[],
    appState: ApplicationState,
    targetUrl: string
  ): Finding[] {
    const findings: Finding[] = [];
    const timestamp = new Date().toISOString();
    const ts = { firstSeen: timestamp, lastSeen: timestamp };

    // 1. Correlate Sensitive Data Exposure
    const sensitiveGroups = secretMatches.filter(g => !g.ruleName.startsWith('keyword_'));
    const keywordGroups = secretMatches.filter(g => g.ruleName.startsWith('keyword_'));

    if (sensitiveGroups.length > 0) {
      const evidence: Evidence[] = [];
      const sources = new Set<DevToolsSurface>();
      const counts: Record<string, number> = {};

      for (const group of sensitiveGroups) {
        counts[group.ruleName] = group.totalCount;
        for (const sample of group.samples) {
          sources.add(sample.sourceType);
          evidence.push({
            surface: sample.sourceType,
            type: 'regex_match',
            description: `Found ${group.ruleName}`,
            source: sample.sourceIdentifier,
            location: sample.location,
            maskedValue: sample.maskedValue,
            snippet: sample.snippet,
            timestamp: sample.timestamp,
          });
        }
      }

      findings.push({
        id: uuidv4(),
        title: 'Potential Sensitive Data Exposure',
        category: FindingCategory.SENSITIVE_DATA_EXPOSURE,
        severity: Severity.HIGH, // Will be adjusted by risk engine
        confidence: sources.size > 1 ? Confidence.HIGH : Confidence.MEDIUM, // Higher confidence if across multiple surfaces
        description: 'Sensitive data patterns (like PII, credentials, or tokens) were detected in the application.',
        impact: 'Exposure of sensitive data can lead to privacy violations, credential theft, or unauthorized access.',
        remediation: 'Ensure that sensitive data is not unnecessarily exposed to the client-side browser context. Validate server-side authorization controls.',
        evidence,
        sources: Array.from(sources),
        counts,
        timestamps: ts,
      });
    }

    // 2. Correlate Auth/Session State
    if (authIndicators.hasAuthStorage || authIndicators.hasAuthCookies) {
      const evidence: Evidence[] = [];
      const sources = new Set<DevToolsSurface>([DevToolsSurface.APPLICATION]);
      const counts: Record<string, number> = {};

      for (const evidenceStr of authIndicators.evidence) {
        evidence.push({
          surface: DevToolsSurface.APPLICATION,
          type: 'auth_indicator',
          description: evidenceStr,
          source: 'Client Storage',
        });
      }

      findings.push({
        id: uuidv4(),
        title: 'Client-Side Authentication State Exposed',
        category: FindingCategory.AUTHENTICATION_STATE_EXPOSURE,
        severity: Severity.MEDIUM,
        confidence: Confidence.HIGH,
        description: 'Authentication or session state indicators were found in client-side storage (Cookies, LocalStorage, etc.).',
        impact: 'While normal for SPAs, excessive auth state or roles stored client-side may indicate reliance on client-side security controls.',
        remediation: 'Do not rely on client-side state for authorization. All access control must be enforced on the server.',
        evidence,
        sources: Array.from(sources),
        counts,
        timestamps: ts,
      });
    }

    // 3. Correlate Suspicious Endpoints
    const suspiciousEndpoints = endpoints.filter(e => e.isSuspicious);
    if (suspiciousEndpoints.length > 0) {
      const evidence: Evidence[] = [];
      const sources = new Set<DevToolsSurface>();
      const counts: Record<string, number> = { suspicious_endpoints: suspiciousEndpoints.length };

      let hasNetworkTraffic = false;

      for (const ep of suspiciousEndpoints) {
        const surface = ep.sourceType === 'network_traffic' ? DevToolsSurface.NETWORK : DevToolsSurface.SOURCES;
        sources.add(surface);
        if (surface === DevToolsSurface.NETWORK) hasNetworkTraffic = true;

        evidence.push({
          surface,
          type: 'suspicious_endpoint',
          description: `Suspicious endpoint: ${ep.classification.join(', ')}`,
          source: ep.sourceUrl || ep.url,
          snippet: ep.snippet,
        });
      }

      findings.push({
        id: uuidv4(),
        title: 'Suspicious Endpoints Exposed',
        category: FindingCategory.INTERNAL_INFRASTRUCTURE,
        severity: Severity.MEDIUM,
        confidence: hasNetworkTraffic ? Confidence.HIGH : Confidence.MEDIUM,
        description: 'Endpoints resembling internal, administrative, or debug interfaces were discovered.',
        impact: 'Exposure of internal endpoints may expand the attack surface.',
        remediation: 'Ensure internal APIs are not exposed publicly and require proper authentication.',
        evidence,
        sources: Array.from(sources),
        counts,
        timestamps: ts,
      });
    }

    // 4. Cookie Security
    const insecureCookies: CapturedCookie[] = appState.cookies.filter(c => c.securityIssues.length > 0);
    if (insecureCookies.length > 0) {
      const evidence: Evidence[] = [];
      
      for (const cookie of insecureCookies) {
        evidence.push({
          surface: DevToolsSurface.APPLICATION,
          type: 'insecure_cookie',
          description: `Cookie "${cookie.name}" issues: ${cookie.securityIssues.join(', ')}`,
          source: cookie.domain,
        });
      }

      findings.push({
        id: uuidv4(),
        title: 'Insecure Session Cookie Configuration',
        category: FindingCategory.SESSION_SECURITY,
        severity: Severity.HIGH,
        confidence: Confidence.HIGH,
        description: 'Session or authentication cookies are missing important security attributes (HttpOnly, Secure).',
        impact: 'Missing HttpOnly allows XSS attacks to steal session tokens. Missing Secure allows interception over unencrypted connections.',
        remediation: 'Set the HttpOnly and Secure flags on all session and authentication cookies.',
        evidence,
        sources: [DevToolsSurface.APPLICATION],
        counts: { insecure_cookies: insecureCookies.length },
        timestamps: ts,
      });
    }

    // 5. Security Headers
    const headerWarnings = securityHeaders.filter(h => h.assessment === 'missing' || h.assessment === 'warning' || h.assessment === 'misconfigured');
    if (headerWarnings.length > 0) {
      const evidence: Evidence[] = [];
      
      for (const header of headerWarnings) {
        evidence.push({
          surface: DevToolsSurface.NETWORK,
          type: 'security_header',
          description: header.description,
          source: targetUrl,
        });
      }

      findings.push({
        id: uuidv4(),
        title: 'Missing or Misconfigured Security Headers',
        category: FindingCategory.SECURITY_CONFIGURATION,
        severity: Severity.LOW,
        confidence: Confidence.HIGH,
        description: 'The server response is missing recommended HTTP security headers.',
        impact: 'Missing security headers reduce the browser\'s ability to protect the user from certain attacks (XSS, clickjacking).',
        remediation: 'Implement recommended security headers (CSP, HSTS, X-Frame-Options, etc.).',
        evidence,
        sources: [DevToolsSurface.NETWORK],
        counts: { header_issues: headerWarnings.length },
        timestamps: ts,
      });
    }

    // 6. Keywords (Info level)
    if (keywordGroups.length > 0) {
      const evidence: Evidence[] = [];
      const sources = new Set<DevToolsSurface>();
      const counts: Record<string, number> = {};

      for (const group of keywordGroups) {
        counts[group.ruleName] = group.totalCount;
        for (const sample of group.samples.slice(0, 3)) { // Limit evidence for keywords to avoid noise
          sources.add(sample.sourceType);
          evidence.push({
            surface: sample.sourceType,
            type: 'keyword_match',
            description: `Found keyword pattern: ${group.ruleName}`,
            source: sample.sourceIdentifier,
            snippet: sample.snippet,
          });
        }
      }

      findings.push({
        id: uuidv4(),
        title: 'Security-Relevant Keywords Detected',
        category: FindingCategory.DEBUG_INFORMATION,
        severity: Severity.INFO,
        confidence: Confidence.LOW,
        description: 'Keywords indicating potential security relevance (e.g., "password", "admin", "internal") were found.',
        impact: 'May indicate exposed debug information or internal paths. Requires manual verification.',
        remediation: 'Review exposed information to ensure no actual secrets or sensitive paths are leaked.',
        evidence,
        sources: Array.from(sources),
        counts,
        timestamps: ts,
      });
    }

    return findings;
  }
}
