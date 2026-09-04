/**
 * @module page-manager
 * Handles page navigation, redirect tracking, and stabilization.
 */

import { Page, BrowserContext, Response } from 'playwright';
import { ScanConfig } from '../config';
import { NavigationInfo, RedirectInfo } from '../models/findings';
import { logger } from '../utils/logger';

export interface NavigationResult {
  page: Page;
  navigationInfo: NavigationInfo;
}

export class PageManager {
  private page: Page | null = null;

  constructor(
    private context: BrowserContext,
    private config: ScanConfig
  ) {}

  /**
   * Navigate to the target URL, capturing redirects and navigation status.
   * @returns Navigation result with page and info
   */
  async navigate(): Promise<NavigationResult> {
    this.page = await this.context.newPage();
    const redirectChain: RedirectInfo[] = [];

    // Track redirects
    this.page.on('response', (response: Response) => {
      const status = response.status();
      if (status >= 300 && status < 400) {
        redirectChain.push({
          url: response.url(),
          status,
          statusText: response.statusText(),
        });
      }
    });

    logger.info(`Navigating to: ${this.config.targetUrl}`);

    let navigationResponse: Response | null = null;
    let navigationSuccessful = true;

    try {
      navigationResponse = await this.page.goto(this.config.targetUrl, {
        timeout: this.config.timeout,
        waitUntil: 'domcontentloaded',
      });
    } catch (err) {
      logger.warn(`Navigation issue: ${err instanceof Error ? err.message : String(err)}`);
      navigationSuccessful = false;
    }

    // Wait for network idle with timeout fallback
    try {
      await this.page.waitForLoadState('networkidle', {
        timeout: this.config.networkIdleTimeout,
      });
      logger.debug('Network idle achieved');
    } catch {
      logger.debug('Network idle timeout - continuing (this is normal for some pages)');
    }

    // Configurable stabilization delay
    if (this.config.waitMs > 0) {
      logger.debug(`Waiting ${this.config.waitMs}ms for stabilization...`);
      await this.page.waitForTimeout(this.config.waitMs);
    }

    // Collect navigation info
    let pageTitle = '';
    try {
      pageTitle = await this.page.title();
    } catch {
      pageTitle = '[unable to retrieve]';
    }

    const navigationInfo: NavigationInfo = {
      requestedUrl: this.config.targetUrl,
      finalUrl: this.page.url(),
      statusCode: navigationResponse?.status() ?? null,
      statusText: navigationResponse?.statusText() ?? '',
      pageTitle,
      redirectChain,
      navigationSuccessful,
    };

    logger.success(`Navigation complete: ${navigationInfo.statusCode ?? 'unknown'} - ${navigationInfo.finalUrl}`);

    return { page: this.page, navigationInfo };
  }

  /**
   * Get the current page.
   */
  getPage(): Page | null {
    return this.page;
  }
}
