#!/usr/bin/env node

/**
 * @module index
 * Main entry point for DevInspect Security Auditor.
 * Orchestrates CLI parsing and the scan lifecycle.
 */

import { Command } from 'commander';
import { ScanConfig, DEFAULT_CONFIG } from './config';
import { logger, setVerbose, setLogLevel, LogLevel } from './utils/logger';
import { RedactionMode, setRedactionMode } from './utils/redaction';
import { ScanResult, DevToolsSurface, MatchGroup, Severity } from './models/findings';
import { BrowserManager } from './browser/browser-manager';
import { PageManager } from './browser/page-manager';
import { NetworkCapture } from './browser/network-capture';
import { RuntimeCapture } from './browser/runtime-capture';
import { ElementsCollector } from './collectors/elements-collector';
import { SourcesCollector } from './collectors/sources-collector';
import { NetworkCollector } from './collectors/network-collector';
import { ApplicationCollector } from './collectors/application-collector';
import { ConsoleCollector } from './collectors/console-collector';
import { SecretAnalyzer } from './analyzers/secret-analyzer';
import { AuthAnalyzer } from './analyzers/auth-analyzer';
import { SecurityHeaderAnalyzer } from './analyzers/security-header-analyzer';
import { StorageAnalyzer } from './analyzers/storage-analyzer';
import { EndpointAnalyzer } from './analyzers/endpoint-analyzer';
import { CorrelationEngine } from './analyzers/correlation-engine';
import { RiskEngine } from './analyzers/risk-engine';
import { TerminalReporter } from './reporting/terminal-reporter';
import { JsonReporter } from './reporting/json-reporter';
import { HtmlReporter } from './reporting/html-reporter';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const pkg = require('../package.json');

async function main() {
  const program = new Command();

  program
    .name('devinspect')
    .description(pkg.description)
    .version(pkg.version)
    .argument('<url>', 'Target URL to audit (must include protocol, e.g., https://...)')
    .option('--headed', 'Run browser in headed mode (visible UI)', false)
    .option('--timeout <ms>', 'Navigation timeout in milliseconds', String(DEFAULT_CONFIG.timeout))
    .option('--network-idle-timeout <ms>', 'Network idle timeout in ms', String(DEFAULT_CONFIG.networkIdleTimeout))
    .option('--wait <ms>', 'Additional wait time after page load for stabilization', String(DEFAULT_CONFIG.waitMs))
    .option('--output <path>', 'JSON report output path', DEFAULT_CONFIG.outputPath)
    .option('--html <path>', 'HTML report output path', DEFAULT_CONFIG.htmlPath)
    .option('--max-body-size <bytes>', 'Maximum response body size to capture in bytes', String(DEFAULT_CONFIG.maxBodySize))
    .option('--redaction <mode>', 'Redaction mode: safe, balanced, forensic', DEFAULT_CONFIG.redactionMode)
    .option('--verbose', 'Enable verbose debug logging', false)
    .option('--ignore-https-errors', 'Ignore HTTPS certificate errors', false)
    .option('--user-agent <string>', 'Custom User-Agent string')
    .action(async (url, options) => {
      // Validate URL
      let targetUrl = url;
      try {
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
          targetUrl = 'https://' + targetUrl;
        }
        new URL(targetUrl);
      } catch {
        console.error(`Invalid URL provided: ${url}`);
        process.exit(1);
      }

      // Build Config
      const config: ScanConfig = {
        ...DEFAULT_CONFIG,
        targetUrl,
        headless: !options.headed,
        timeout: parseInt(options.timeout, 10),
        networkIdleTimeout: parseInt(options.networkIdleTimeout, 10),
        waitMs: parseInt(options.wait, 10),
        outputPath: options.output,
        htmlPath: options.html,
        maxBodySize: parseInt(options.maxBodySize, 10),
        redactionMode: options.redaction as RedactionMode,
        verbose: options.verbose,
        ignoreHttpsErrors: options.ignoreHttpsErrors,
        userAgent: options.userAgent,
      };

      // Set global utilities state
      setVerbose(config.verbose);
      setRedactionMode(config.redactionMode);

      // Sanity check redaction
      if (config.redactionMode === RedactionMode.FORENSIC) {
        logger.warn('FORENSIC redaction mode enabled. Secrets will be minimally masked in JSON/HTML reports.');
      }

      await runAudit(config);
    });

  await program.parseAsync(process.argv);
}

async function runAudit(config: ScanConfig): Promise<void> {
  const startTime = Date.now();
  const warnings: string[] = [];

  const browserManager = new BrowserManager(config);
  let scanResult: ScanResult | null = null;

  try {
    // 1. Setup & Launch
    const context = await browserManager.launch();
    const pageManager = new PageManager(context, config);
    
    // Setup capture before navigation
    const networkCapture = new NetworkCapture(config);
    const runtimeCapture = new RuntimeCapture(config);
    
    // We create a new page manually here to attach listeners early
    const page = await context.newPage();
    networkCapture.attach(page);
    runtimeCapture.attach(page);

    // Override page manager's page creation
    (pageManager as any).page = page;
    
    // 2. Navigate
    logger.info(`Starting audit of ${config.targetUrl}`);
    const navResult = await pageManager.navigate();

    if (!navResult.navigationInfo.navigationSuccessful) {
      warnings.push(`Initial navigation to ${config.targetUrl} failed. Analysis may be incomplete.`);
    }

    // 3. Collection Phase
    const elementsCol = new ElementsCollector();
    const sourcesCol = new SourcesCollector();
    const networkCol = new NetworkCollector();
    const appCol = new ApplicationCollector(config);
    const consoleCol = new ConsoleCollector();

    const elementsData = await elementsCol.collect(page);
    const networkData = networkCol.collect(networkCapture);
    const sourcesData = await sourcesCol.collect(networkCapture, elementsData);
    const appData = await appCol.collect(page, context);
    const consoleData = consoleCol.collect(runtimeCapture);

    // 4. Analysis Phase
    logger.info('Running security analyzers...');
    const secretAnalyzer = new SecretAnalyzer(config);
    const authAnalyzer = new AuthAnalyzer();
    const securityHeaderAnalyzer = new SecurityHeaderAnalyzer();
    const storageAnalyzer = new StorageAnalyzer();
    const endpointAnalyzer = new EndpointAnalyzer();

    // 4a. Secret Analysis (Elements, Sources, Network, Storage, Console)
    const rawSecretMatches = [
      ...secretAnalyzer.scan(elementsData.html, 'DOM HTML', DevToolsSurface.ELEMENTS),
      ...sourcesData.resources.flatMap(r => secretAnalyzer.scan(r.body || '', r.url, DevToolsSurface.SOURCES, r.url)),
      ...networkData.entries.flatMap(e => e.response?.body ? secretAnalyzer.scan(e.response.body, e.request.url, DevToolsSurface.NETWORK, e.request.url) : []),
      ...appData.localStorage.flatMap(s => secretAnalyzer.scan(s.rawValue || '', `localStorage:${s.key}`, DevToolsSurface.APPLICATION)),
      ...appData.sessionStorage.flatMap(s => secretAnalyzer.scan(s.rawValue || '', `sessionStorage:${s.key}`, DevToolsSurface.APPLICATION)),
      ...consoleData.messages.flatMap(m => secretAnalyzer.scan(m.text, 'Console Message', DevToolsSurface.CONSOLE)),
    ];
    
    const secretMatchGroups = SecretAnalyzer.groupMatches(rawSecretMatches);

    // 4b. Auth Analysis
    const authIndicators = authAnalyzer.analyze(elementsData, appData, navResult.navigationInfo.finalUrl);

    // 4c. Header Analysis
    const headerResults = securityHeaderAnalyzer.analyze(networkData, navResult.navigationInfo.finalUrl);

    // 4d. Storage Analysis
    storageAnalyzer.analyze(appData);

    // 4e. Endpoint Analysis
    const analyzedEndpoints = endpointAnalyzer.analyze(sourcesData, networkData);

    // 5. Correlation & Risk Phase
    logger.info('Correlating findings...');
    const correlationEngine = new CorrelationEngine();
    let findings = correlationEngine.correlate(
      secretMatchGroups,
      authIndicators,
      analyzedEndpoints,
      headerResults,
      appData,
      navResult.navigationInfo.finalUrl
    );

    const riskEngine = new RiskEngine();
    findings = riskEngine.evaluate(findings);

    // 6. Build Result
    const endTime = Date.now();
    scanResult = {
      metadata: {
        toolName: pkg.name,
        toolVersion: pkg.version,
        targetUrl: config.targetUrl,
        scanStartTime: new Date(startTime).toISOString(),
        scanEndTime: new Date(endTime).toISOString(),
        scanDurationMs: endTime - startTime,
      },
      navigation: navResult.navigationInfo,
      collections: {
        elements: { formsCount: elementsData.forms.length, inputsCount: elementsData.inputs.length, scriptsCount: elementsData.scripts.length },
        sources: { resourcesCount: sourcesData.resources.length, endpointsCount: sourcesData.endpoints.length },
        network: networkData.summary,
        application: {
          cookiesCount: appData.cookies.length,
          localStorageCount: appData.localStorage.length,
          sessionStorageCount: appData.sessionStorage.length,
        },
        console: consoleData.summary,
      },
      findings,
      summary: {
        totalFindings: findings.length,
        bySeverity: {
          [Severity.CRITICAL]: findings.filter(f => f.severity === Severity.CRITICAL).length,
          [Severity.HIGH]: findings.filter(f => f.severity === Severity.HIGH).length,
          [Severity.MEDIUM]: findings.filter(f => f.severity === Severity.MEDIUM).length,
          [Severity.LOW]: findings.filter(f => f.severity === Severity.LOW).length,
          [Severity.INFO]: findings.filter(f => f.severity === Severity.INFO).length,
        },
        byCategory: findings.reduce((acc, f) => { acc[f.category] = (acc[f.category] || 0) + 1; return acc; }, {} as Record<string, number>),
        bySurface: findings.reduce((acc, f) => { 
          f.sources.forEach(s => { acc[s] = (acc[s] || 0) + 1; });
          return acc; 
        }, {} as Record<string, number>),
        surfaceStatus: {
          elements: true,
          sources: sourcesData.resources.length > 0,
          network: networkData.entries.length > 0,
          application: true,
          console: true,
        },
        uniqueMatchesByRule: secretMatchGroups.reduce((acc, g) => { acc[g.ruleName] = g.uniqueCount; return acc; }, {} as Record<string, number>),
      },
      warnings,
      config: config as unknown as Record<string, unknown>,
    };

    // 7. Reporting
    logger.info('Generating reports...');
    const termReporter = new TerminalReporter();
    termReporter.report(scanResult!);

    const jsonReporter = new JsonReporter();
    await jsonReporter.report(scanResult!, config.outputPath);

    const htmlReporter = new HtmlReporter();
    await htmlReporter.report(scanResult!, config.htmlPath);

  } catch (err) {
    logger.error(`Scan failed: ${err instanceof Error ? err.stack : String(err)}`);
    process.exitCode = 1;
  } finally {
    // 8. Cleanup
    await browserManager.close();
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
