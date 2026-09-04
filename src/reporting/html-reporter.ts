/**
 * @module html-reporter
 * Generates a self-contained HTML report.
 */

import { promises as fs } from 'fs';
import { ScanResult, Severity, Finding } from '../models/findings';
import { logger } from '../utils/logger';

export class HtmlReporter {
  async report(result: ScanResult, outputPath: string): Promise<void> {
    logger.info(`Generating HTML report at ${outputPath}...`);
    
    try {
      const htmlContent = this.generateHtml(result);
      await fs.writeFile(outputPath, htmlContent, 'utf-8');
      logger.success(`HTML report saved to ${outputPath}`);
    } catch (err) {
      logger.error(`Failed to save HTML report: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private generateHtml(result: ScanResult): string {
    const resultJson = JSON.stringify(result);

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DevInspect Security Auditor Report</title>
  <style>
    :root {
      --bg: #f8fafc;
      --surface: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --primary: #3b82f6;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #94a3b8;
    }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      margin: 0;
      padding: 0;
    }
    header {
      background-color: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 2rem;
      text-align: center;
    }
    h1 { margin: 0 0 0.5rem 0; font-size: 1.5rem; }
    h2 { font-size: 1.25rem; border-bottom: 2px solid var(--border); padding-bottom: 0.5rem; margin-top: 2rem;}
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
    }
    .card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
    }
    .stat-box {
      text-align: center;
      padding: 1rem;
      border-radius: 0.5rem;
      border: 1px solid var(--border);
    }
    .stat-val { font-size: 2rem; font-weight: bold; }
    .stat-label { font-size: 0.875rem; color: var(--text-muted); text-transform: uppercase; }
    
    .sev-CRITICAL { color: var(--critical); border-color: var(--critical); background: #fef2f2; }
    .sev-HIGH { color: var(--high); border-color: var(--high); background: #fff7ed; }
    .sev-MEDIUM { color: var(--medium); border-color: var(--medium); background: #fefce8; }
    .sev-LOW { color: var(--low); border-color: var(--low); background: #eff6ff; }
    .sev-INFO { color: var(--info); border-color: var(--info); background: #f8fafc; }
    
    .badge {
      display: inline-block;
      padding: 0.25rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: bold;
      border: 1px solid currentColor;
    }
    
    .finding { margin-bottom: 2rem; }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1rem;}
    .finding-title { font-size: 1.125rem; font-weight: bold; margin: 0; }
    
    pre {
      background: #1e293b;
      color: #e2e8f0;
      padding: 1rem;
      border-radius: 0.25rem;
      overflow-x: auto;
      font-size: 0.875rem;
    }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
    
    .evidence-list { list-style-type: none; padding: 0; }
    .evidence-item {
      border-left: 3px solid var(--border);
      padding-left: 1rem;
      margin-bottom: 1rem;
    }
    .surface-badge {
      background: var(--border);
      color: var(--text);
      padding: 0.1rem 0.4rem;
      border-radius: 0.25rem;
      font-size: 0.75rem;
      margin-right: 0.5rem;
    }
  </style>
</head>
<body>
  <header>
    <h1>DevInspect Security Auditor</h1>
    <div style="color: var(--text-muted)">Target: ${this.escapeHtml(result.metadata.targetUrl)}</div>
    <div style="color: var(--text-muted); font-size: 0.875rem; margin-top: 0.5rem;">
      Scan completed in ${result.metadata.scanDurationMs}ms on ${new Date().toLocaleString()}
    </div>
  </header>

  <div class="container">
    <div class="card warning" style="border-color: var(--high); background: #fff7ed;">
      <strong>⚠️ Authorized Use Only:</strong> This tool identifies security indicators from information exposed to the browser. It does not prove server-side authorization correctness by itself.
    </div>

    <h2>Risk Summary</h2>
    <div class="summary-grid">
      <div class="stat-box sev-CRITICAL">
        <div class="stat-val">${result.summary.bySeverity.CRITICAL || 0}</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-box sev-HIGH">
        <div class="stat-val">${result.summary.bySeverity.HIGH || 0}</div>
        <div class="stat-label">High</div>
      </div>
      <div class="stat-box sev-MEDIUM">
        <div class="stat-val">${result.summary.bySeverity.MEDIUM || 0}</div>
        <div class="stat-label">Medium</div>
      </div>
      <div class="stat-box sev-LOW">
        <div class="stat-val">${result.summary.bySeverity.LOW || 0}</div>
        <div class="stat-label">Low</div>
      </div>
      <div class="stat-box sev-INFO">
        <div class="stat-val">${result.summary.bySeverity.INFO || 0}</div>
        <div class="stat-label">Info</div>
      </div>
    </div>

    <h2>Findings</h2>
    <div id="findings-container">
      ${result.findings.map(f => this.renderFinding(f)).join('\n')}
      ${result.findings.length === 0 ? '<p>No findings detected.</p>' : ''}
    </div>
  </div>

  <script>
    // Embedded result data for interactive filtering if needed later
    window.__SCAN_RESULT__ = ${resultJson.replace(/</g, '\\u003c')};
  </script>
</body>
</html>`;
  }

  private renderFinding(finding: Finding): string {
    return `
    <div class="card finding">
      <div class="finding-header">
        <h3 class="finding-title">${this.escapeHtml(finding.title)}</h3>
        <div>
          <span class="badge sev-${finding.severity}">${finding.severity}</span>
          <span class="badge" style="color: var(--text-muted)">Conf: ${finding.confidence}</span>
        </div>
      </div>
      
      <p><strong>Description:</strong> ${this.escapeHtml(finding.description)}</p>
      <p><strong>Impact:</strong> ${this.escapeHtml(finding.impact)}</p>
      <p><strong>Remediation:</strong> ${this.escapeHtml(finding.remediation)}</p>
      
      <h4>Evidence</h4>
      <ul class="evidence-list">
        ${finding.evidence.map(ev => `
          <li class="evidence-item">
            <div><span class="surface-badge">${ev.surface}</span> <strong>${this.escapeHtml(ev.description)}</strong></div>
            ${ev.source ? `<div style="font-size: 0.875rem; color: var(--text-muted); margin-top: 0.25rem;">Source: ${this.escapeHtml(ev.source)}</div>` : ''}
            ${ev.snippet ? `<pre><code>${this.escapeHtml(ev.snippet)}</code></pre>` : ''}
          </li>
        `).join('')}
      </ul>
    </div>`;
  }

  private escapeHtml(unsafe: string): string {
    if (!unsafe) return '';
    return unsafe
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
}
