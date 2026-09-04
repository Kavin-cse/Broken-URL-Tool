/**
 * @module console-collector
 * Collects and structures console messages and page errors.
 */

import { RuntimeCapture } from '../browser/runtime-capture';
import { CapturedConsoleMessage, CapturedPageError } from '../models/sources';
import { logger } from '../utils/logger';

export interface ConsoleData {
  messages: CapturedConsoleMessage[];
  errors: CapturedPageError[];
  summary: {
    totalMessages: number;
    byLevel: Record<string, number>;
    totalErrors: number;
  };
}

export class ConsoleCollector {
  collect(runtimeCapture: RuntimeCapture): ConsoleData {
    logger.info('Collecting Console data...');

    const messages = runtimeCapture.getConsoleMessages();
    const errors = runtimeCapture.getPageErrors();

    const summary = {
      totalMessages: messages.length,
      byLevel: {} as Record<string, number>,
      totalErrors: errors.length,
    };

    for (const msg of messages) {
      summary.byLevel[msg.level] = (summary.byLevel[msg.level] || 0) + 1;
    }

    logger.debug(`Collected ${messages.length} console messages, ${errors.length} page errors`);

    return {
      messages,
      errors,
      summary,
    };
  }
}
