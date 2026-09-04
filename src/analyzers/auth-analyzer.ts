/**
 * @module auth-analyzer
 * Passive authentication and authorization indicator detection.
 */

import { ElementsData } from '../collectors/elements-collector';
import { ApplicationState } from '../models/storage';
import { ROUTE_INDICATORS } from '../rules/keywords';

export interface AuthIndicators {
  hasAuthForms: boolean;
  hasAuthFields: boolean;
  hasAuthCookies: boolean;
  hasAuthStorage: boolean;
  hasProtectedRoutes: boolean;
  adminIndicators: string[];
  evidence: string[];
}

export class AuthAnalyzer {
  analyze(elements: ElementsData, appState: ApplicationState, url: string): AuthIndicators {
    const indicators: AuthIndicators = {
      hasAuthForms: false,
      hasAuthFields: false,
      hasAuthCookies: false,
      hasAuthStorage: false,
      hasProtectedRoutes: false,
      adminIndicators: [],
      evidence: [],
    };

    // 1. Check DOM for auth forms (login/register)
    for (const form of elements.forms) {
      const action = form.action.toLowerCase();
      const hasPasswordField = form.inputs.some(i => i.type === 'password');
      if (hasPasswordField || action.includes('login') || action.includes('signin') || action.includes('auth')) {
        indicators.hasAuthForms = true;
        indicators.evidence.push(`DOM contains authentication-related form (action: ${form.action}, hasPassword: ${hasPasswordField})`);
      }
    }

    // 2. Check DOM for auth fields outside forms
    if (!indicators.hasAuthForms) {
      const hasPasswordField = elements.inputs.some(i => i.type === 'password');
      if (hasPasswordField) {
        indicators.hasAuthFields = true;
        indicators.evidence.push('DOM contains standalone password input');
      }
    }

    // 3. Check Cookies
    const authCookies = appState.cookies.filter(c => c.isSessionLike);
    if (authCookies.length > 0) {
      indicators.hasAuthCookies = true;
      indicators.evidence.push(`Found ${authCookies.length} session-like cookies (e.g., ${authCookies[0].name})`);
    }

    // 4. Check Storage
    const allStorage = [...appState.localStorage, ...appState.sessionStorage];
    const authStorage = allStorage.filter(s => 
      s.classification === 'access_token' || 
      s.classification === 'auth_token' || 
      s.classification === 'jwt' ||
      s.classification === 'session' ||
      s.classification === 'role' ||
      s.classification === 'permissions' ||
      s.classification === 'auth_state'
    );

    if (authStorage.length > 0) {
      indicators.hasAuthStorage = true;
      indicators.evidence.push(`Found ${authStorage.length} auth-related storage keys (e.g., ${authStorage[0].key})`);
    }

    // 5. Check URL for protected routes
    const urlLower = url.toLowerCase();
    for (const route of ROUTE_INDICATORS) {
      if (urlLower.includes(route.pattern)) {
        indicators.hasProtectedRoutes = true;
        if (route.category === 'admin') {
          indicators.adminIndicators.push(`URL contains admin pattern: ${route.pattern}`);
        } else {
          indicators.evidence.push(`URL matches protected route pattern: ${route.pattern}`);
        }
      }
    }

    // 6. Check DOM for admin indicators
    for (const link of elements.links) {
      const href = link.href.toLowerCase();
      const text = link.text.toLowerCase();
      if (href.includes('/admin') || text.includes('admin ') || text === 'admin') {
        if (!indicators.adminIndicators.includes('DOM contains admin links')) {
          indicators.adminIndicators.push('DOM contains admin links');
        }
      }
    }

    return indicators;
  }
}
