/**
 * @module risk-engine
 * Evaluates findings to adjust severity and confidence based on correlation context.
 */

import { Finding, Severity, Confidence, FindingCategory } from '../models/findings';

export class RiskEngine {
  evaluate(findings: Finding[]): Finding[] {
    const evaluatedFindings = [...findings];

    for (const finding of evaluatedFindings) {
      this.evaluateFinding(finding);
    }

    // Sort by severity (CRITICAL -> INFO) and then confidence (HIGH -> LOW)
    return evaluatedFindings.sort((a, b) => {
      const severityScores: Record<Severity, number> = {
        [Severity.CRITICAL]: 4,
        [Severity.HIGH]: 3,
        [Severity.MEDIUM]: 2,
        [Severity.LOW]: 1,
        [Severity.INFO]: 0,
      };

      const confidenceScores: Record<Confidence, number> = {
        [Confidence.HIGH]: 2,
        [Confidence.MEDIUM]: 1,
        [Confidence.LOW]: 0,
      };

      const sevA = severityScores[a.severity];
      const sevB = severityScores[b.severity];

      if (sevA !== sevB) {
        return sevB - sevA;
      }

      const confA = confidenceScores[a.confidence];
      const confB = confidenceScores[b.confidence];

      return confB - confA;
    });
  }

  private evaluateFinding(finding: Finding): void {
    if (finding.category === FindingCategory.SENSITIVE_DATA_EXPOSURE) {
      // Adjust severity based on the types of data exposed
      if (finding.counts['private_key'] || finding.counts['aws_access_key'] || finding.counts['credit_card'] || finding.counts['us_ssn']) {
        finding.severity = Severity.CRITICAL;
      } else if (finding.counts['jwt'] || finding.counts['api_key_param'] || finding.counts['bearer_token']) {
        finding.severity = Severity.HIGH;
      } else if (finding.counts['email'] || finding.counts['us_phone']) {
        // High volume of PII increases severity
        const piiCount = (finding.counts['email'] || 0) + (finding.counts['us_phone'] || 0);
        if (piiCount > 50) {
           finding.severity = Severity.HIGH;
        } else if (finding.severity === Severity.HIGH) {
           finding.severity = Severity.MEDIUM; // Downgrade if it's just a few emails
        }
      }
    }

    // Adjust confidence based on multiple sources
    if (finding.sources.length >= 3 && finding.confidence !== Confidence.HIGH) {
      finding.confidence = Confidence.HIGH;
    }
  }
}
