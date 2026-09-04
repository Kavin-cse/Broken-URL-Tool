import { describe, it, expect } from 'vitest';
import { RiskEngine } from '../../src/analyzers/risk-engine';
import { Finding, FindingCategory, Severity, Confidence, DevToolsSurface } from '../../src/models/findings';

describe('RiskEngine', () => {
  const engine = new RiskEngine();

  const baseFinding: Finding = {
    id: '1',
    title: 'Test',
    category: FindingCategory.SENSITIVE_DATA_EXPOSURE,
    severity: Severity.HIGH,
    confidence: Confidence.MEDIUM,
    description: '',
    impact: '',
    remediation: '',
    evidence: [],
    sources: [DevToolsSurface.SOURCES],
    counts: {},
    timestamps: { firstSeen: '', lastSeen: '' },
  };

  it('elevates severity to CRITICAL for private keys', () => {
    const finding = { ...baseFinding, counts: { private_key: 1 } };
    const results = engine.evaluate([finding]);
    expect(results[0].severity).toBe(Severity.CRITICAL);
  });

  it('elevates confidence to HIGH if evidence comes from 3+ surfaces', () => {
    const finding = { 
      ...baseFinding, 
      counts: { some_data: 1 },
      sources: [DevToolsSurface.ELEMENTS, DevToolsSurface.NETWORK, DevToolsSurface.APPLICATION]
    };
    const results = engine.evaluate([finding]);
    expect(results[0].confidence).toBe(Confidence.HIGH);
  });

  it('sorts findings by severity then confidence', () => {
    const lowConfInfo = { ...baseFinding, id: '1', severity: Severity.INFO, confidence: Confidence.LOW };
    const highConfInfo = { ...baseFinding, id: '2', severity: Severity.INFO, confidence: Confidence.HIGH };
    const medConfHigh = { ...baseFinding, id: '3', severity: Severity.HIGH, confidence: Confidence.MEDIUM };
    
    const results = engine.evaluate([lowConfInfo, medConfHigh, highConfInfo]);
    
    expect(results[0].id).toBe('3'); // HIGH / MEDIUM
    expect(results[1].id).toBe('2'); // INFO / HIGH
    expect(results[2].id).toBe('1'); // INFO / LOW
  });
});
