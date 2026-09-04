/**
 * @module browser-manager
 * Manages Playwright browser lifecycle: launch, context creation, and cleanup.
 */

import { chromium, Browser, BrowserContext } from 'playwright';
import { ScanConfig } from '../config';
import { logger } from '../utils/logger';

export class BrowserManager {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;

  constructor(private config: ScanConfig) {}

  /**
   * Launch Chromium and create an isolated browser context.
   * @returns The browser context
   */
  async launch(): Promise<BrowserContext> {
    logger.info('Launching Chromium browser...');

    this.browser = await chromium.launch({
      headless: this.config.headless,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
      ],
    });

    const contextOptions: Record<string, unknown> = {
      ignoreHTTPSErrors: this.config.ignoreHttpsErrors,
      javaScriptEnabled: true,
      bypassCSP: false,
    };

    if (this.config.userAgent) {
      contextOptions.userAgent = this.config.userAgent;
    }

    this.context = await this.browser.newContext(contextOptions);

    logger.success('Browser launched successfully');
    return this.context;
  }

  /**
   * Get the current browser context.
   */
  getContext(): BrowserContext | null {
    return this.context;
  }

  /**
   * Get the underlying browser instance.
   */
  getBrowser(): Browser | null {
    return this.browser;
  }

  /**
   * Close the browser and clean up resources.
   */
  async close(): Promise<void> {
    try {
      if (this.context) {
        await this.context.close();
        this.context = null;
      }
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
      }
      logger.info('Browser closed');
    } catch (err) {
      logger.warn(`Error closing browser: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
