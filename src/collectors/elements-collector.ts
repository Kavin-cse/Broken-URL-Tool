/**
 * @module elements-collector
 * Inspects the rendered DOM for security indicators.
 */

import { Page } from 'playwright';
import { logger } from '../utils/logger';

export interface ElementsData {
  html: string;
  innerText: string;
  forms: DOMForm[];
  links: DOMLink[];
  inputs: DOMInput[];
  iframes: string[];
  scripts: string[];
  comments: string[];
  metaTags: Record<string, string>;
}

export interface DOMForm {
  action: string;
  method: string;
  inputs: DOMInput[];
}

export interface DOMInput {
  name: string;
  type: string;
  id: string;
  value: string;
  hidden: boolean;
  disabled: boolean;
  autocomplete: string;
}

export interface DOMLink {
  href: string;
  text: string;
  ariaLabel: string;
}

export class ElementsCollector {
  async collect(page: Page): Promise<ElementsData> {
    logger.info('Collecting Elements data...');

    let html = '';
    let innerText = '';
    try {
      html = await page.content();
      innerText = await page.evaluate(() => document.body?.innerText || '');
    } catch (err) {
      logger.warn(`Failed to capture full HTML/text: ${err instanceof Error ? err.message : String(err)}`);
    }

    const data: ElementsData = await page.evaluate(() => {
      // 1. Collect Forms
      const forms: DOMForm[] = Array.from(document.forms).map(f => {
        const inputs = Array.from(f.elements).map(e => {
          const el = e as HTMLInputElement;
          return {
            name: el.name || '',
            type: el.type || '',
            id: el.id || '',
            value: el.value || '',
            hidden: el.type === 'hidden' || el.style.display === 'none',
            disabled: el.disabled,
            autocomplete: el.autocomplete || '',
          };
        });
        return {
          action: f.action || '',
          method: f.method || 'GET',
          inputs,
        };
      });

      // 2. Collect generic inputs not in forms
      const standaloneInputs: DOMInput[] = Array.from(document.querySelectorAll('input, select, textarea'))
        .filter(el => !el.closest('form'))
        .map(e => {
          const el = e as HTMLInputElement;
          return {
            name: el.name || '',
            type: el.type || '',
            id: el.id || '',
            value: el.value || '',
            hidden: el.type === 'hidden' || el.style.display === 'none',
            disabled: el.disabled,
            autocomplete: el.autocomplete || '',
          };
        });

      // 3. Collect links
      const links: DOMLink[] = Array.from(document.querySelectorAll('a')).map(a => ({
        href: a.href || '',
        text: a.innerText || '',
        ariaLabel: a.getAttribute('aria-label') || '',
      }));

      // 4. Collect iframes
      const iframes: string[] = Array.from(document.querySelectorAll('iframe'))
        .map(i => i.src)
        .filter(src => src);

      // 5. Collect inline scripts
      const scripts: string[] = Array.from(document.querySelectorAll('script:not([src])'))
        .map(s => s.innerHTML)
        .filter(text => text.trim().length > 0);

      // 6. Collect comments
      const comments: string[] = [];
      const iterator = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT, null);
      let currentNode;
      while ((currentNode = iterator.nextNode())) {
        if (currentNode.nodeValue && currentNode.nodeValue.trim()) {
          comments.push(currentNode.nodeValue.trim());
        }
      }

      // 7. Collect meta tags
      const metaTags: Record<string, string> = {};
      Array.from(document.querySelectorAll('meta')).forEach(m => {
        const name = m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv');
        const content = m.getAttribute('content');
        if (name && content) {
          metaTags[name] = content;
        }
      });

      return {
        html: '', // Will be populated from outside evaluation
        innerText: '', // Will be populated from outside evaluation
        forms,
        links,
        inputs: standaloneInputs,
        iframes,
        scripts,
        comments,
        metaTags,
      };
    });

    data.html = html;
    data.innerText = innerText;

    logger.debug(`Collected ${data.forms.length} forms, ${data.links.length} links, ${data.comments.length} comments`);
    return data;
  }
}
