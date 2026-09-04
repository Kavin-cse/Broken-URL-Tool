/**
 * @module runtime-capture
 * Captures console messages and page errors via Playwright events.
 */

import { Page, ConsoleMessage } from 'playwright';
import { ScanConfig } from '../config';
import { CapturedConsoleMessage, CapturedPageError } from '../models/sources';
import { logger } from '../utils/logger';
import { truncate } from '../utils/snippets';

export class RuntimeCapture {
  private consoleMessages: CapturedConsoleMessage[] = [];
  private pageErrors: CapturedPageError[] = [];

  constructor(private config: ScanConfig) {}

  /**
   * Attach console and error listeners to a page.
   * Must be called before navigation.
   */
  attach(page: Page): void {
    page.on('console', (msg: ConsoleMessage) => {
      if (this.consoleMessages.length >= this.config.maxConsoleMessages) {
        return;
      }

      let args: string[] | undefined;
      try {
        args = msg.args().map(arg => {
          try {
            return truncate(arg.toString(), 500);
          } catch {
            return '[unserializable]';
          }
        });
      } catch {
        args = undefined;
      }

      const captured: CapturedConsoleMessage = {
        level: msg.type(),
        text: truncate(msg.text(), 2000),
        timestamp: new Date().toISOString(),
        sourceLocation: msg.location()
          ? `${msg.location().url}:${msg.location().lineNumber}:${msg.location().columnNumber}`
          : undefined,
        args,
      };

      this.consoleMessages.push(captured);
    });

    page.on('pageerror', (error: Error) => {
      this.pageErrors.push({
        message: truncate(error.message, 2000),
        stack: error.stack ? truncate(error.stack, 3000) : undefined,
        timestamp: new Date().toISOString(),
      });
    });

    logger.debug('Runtime capture attached');
  }

  /**
   * Get all captured console messages.
   */
  getConsoleMessages(): CapturedConsoleMessage[] {
    return this.consoleMessages;
  }

  /**
   * Get all captured page errors.
   */
  getPageErrors(): CapturedPageError[] {
    return this.pageErrors;
  }
}
