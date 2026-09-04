/**
 * @module json-reporter
 * Generates a structured JSON report.
 */

import { promises as fs } from 'fs';
import { ScanResult } from '../models/findings';
import { logger } from '../utils/logger';

export class JsonReporter {
  async report(result: ScanResult, outputPath: string): Promise<void> {
    logger.info(`Generating JSON report at ${outputPath}...`);
    
    try {
      const jsonStr = JSON.stringify(result, null, 2);
      await fs.writeFile(outputPath, jsonStr, 'utf-8');
      logger.success(`JSON report saved to ${outputPath}`);
    } catch (err) {
      logger.error(`Failed to save JSON report: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
