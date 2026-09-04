/**
 * @module terminal-reporter
 * Generates formatted terminal output for the scan results.
 */

import chalk from 'chalk';
import Table from 'cli-table3';
import { ScanResult, Severity, Finding } from '../models/findings';

export class TerminalReporter {
  report(result: ScanResult): void {
    console.log('\n' + '='.repeat(60));
    console.log(chalk.bold('DEVINSPECT SECURITY AUDITOR'));
    console.log('='.repeat(60) + '\n');

    console.log(chalk.bold('Target:'));
    console.log(result.metadata.targetUrl);

    console.log('\n' + chalk.bold('Navigation:'));
    console.log(`  Final URL: ${result.navigation.finalUrl}`);
    console.log(`  Status:    ${this.colorizeStatus(result.navigation.statusCode)}`);
    console.log(`  Title:     ${result.navigation.pageTitle}`);

    console.log('\n' + chalk.bold('DevTools surfaces:'));
    const surfaces = result.summary.surfaceStatus;
    console.log(`  Elements     ${surfaces.elements ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  Sources      ${surfaces.sources ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  Network      ${surfaces.network ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  Application  ${surfaces.application ? chalk.green('✓') : chalk.red('✗')}`);
    console.log(`  Console      ${surfaces.console ? chalk.green('✓') : chalk.red('✗')}`);

    console.log('\n' + '-'.repeat(60));
    console.log(chalk.bold('RISK SUMMARY'));
    console.log('-'.repeat(60) + '\n');

    const bySev = result.summary.bySeverity;
    console.log(chalk.red.bold(`CRITICAL: ${bySev.CRITICAL || 0}`));
    console.log(chalk.red(`HIGH:     ${bySev.HIGH || 0}`));
    console.log(chalk.yellow(`MEDIUM:   ${bySev.MEDIUM || 0}`));
    console.log(chalk.blue(`LOW:      ${bySev.LOW || 0}`));
    console.log(chalk.gray(`INFO:     ${bySev.INFO || 0}`));

    // Only print HIGH and CRITICAL findings by default in terminal, or MEDIUM if no high ones
    const highConfFindings = result.findings.filter(
      f => f.severity === Severity.CRITICAL || f.severity === Severity.HIGH || f.severity === Severity.MEDIUM
    );

    if (highConfFindings.length > 0) {
      console.log('\n' + '-'.repeat(60));
      console.log(chalk.bold('NOTABLE FINDINGS'));
      console.log('-'.repeat(60) + '\n');

      for (const finding of highConfFindings) {
        this.printFinding(finding);
      }
    } else {
      console.log('\n' + chalk.green('No CRITICAL, HIGH, or MEDIUM findings detected.'));
    }

    if (result.warnings.length > 0) {
      console.log('\n' + '-'.repeat(60));
      console.log(chalk.yellow.bold('WARNINGS'));
      console.log('-'.repeat(60));
      for (const warn of result.warnings.slice(0, 5)) {
        console.log(chalk.yellow(`  ! ${warn}`));
      }
      if (result.warnings.length > 5) {
        console.log(chalk.yellow(`  ... and ${result.warnings.length - 5} more warnings.`));
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log(`Scan completed in ${result.metadata.scanDurationMs}ms`);
    console.log(`Full reports saved to JSON and HTML.`);
    console.log('='.repeat(60) + '\n');
  }

  private printFinding(finding: Finding): void {
    const sevColor = this.getSeverityColor(finding.severity);
    console.log(sevColor(`[${finding.severity}] ${chalk.bold(finding.title)}`));
    
    // Group evidence by surface
    const evidenceBySurface: Record<string, string[]> = {};
    for (const ev of finding.evidence) {
      if (!evidenceBySurface[ev.surface]) evidenceBySurface[ev.surface] = [];
      
      let evStr = `  - ${ev.description}`;
      if (ev.source) evStr += `\n      Source: ${ev.source}`;
      if (ev.snippet) evStr += `\n      Snippet: ${chalk.gray(ev.snippet)}`;
      
      if (!evidenceBySurface[ev.surface].includes(evStr)) {
        evidenceBySurface[ev.surface].push(evStr);
      }
    }

    if (Object.keys(evidenceBySurface).length > 0) {
      console.log('\nEvidence:');
      for (const [surface, evs] of Object.entries(evidenceBySurface)) {
        console.log(`  ${chalk.bold(surface)}:`);
        for (const ev of evs.slice(0, 3)) { // Limit to 3 pieces of evidence per surface in terminal
          console.log(ev);
        }
        if (evs.length > 3) {
          console.log(`    ... and ${evs.length - 3} more items`);
        }
      }
    }

    if (Object.keys(finding.counts).length > 0) {
      console.log('\nData indicators:');
      for (const [key, count] of Object.entries(finding.counts)) {
        console.log(`  ${key}: ${count}`);
      }
    }

    console.log('\n' + '-'.repeat(60) + '\n');
  }

  private colorizeStatus(status: number | null): string {
    if (status === null) return chalk.gray('unknown');
    if (status >= 200 && status < 300) return chalk.green(status.toString());
    if (status >= 300 && status < 400) return chalk.yellow(status.toString());
    if (status >= 400) return chalk.red(status.toString());
    return status.toString();
  }

  private getSeverityColor(severity: Severity): chalk.Chalk {
    switch (severity) {
      case Severity.CRITICAL: return chalk.red.bold;
      case Severity.HIGH: return chalk.red;
      case Severity.MEDIUM: return chalk.yellow;
      case Severity.LOW: return chalk.blue;
      case Severity.INFO: return chalk.gray;
      default: return chalk.white;
    }
  }
}
