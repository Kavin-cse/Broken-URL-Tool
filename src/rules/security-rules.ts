/**
 * @module security-rules
 * Rules for cookie security, header security, and storage security analysis.
 */

/** Cookie names that suggest session/authentication cookies */
export const SESSION_COOKIE_PATTERNS: RegExp[] = [
  /^session$/i,
  /^sessionid$/i,
  /^session_id$/i,
  /^sid$/i,
  /^auth$/i,
  /^auth_token$/i,
  /^access_token$/i,
  /^refresh_token$/i,
  /^jwt$/i,
  /^token$/i,
  /^connect\.sid$/i,
  /^JSESSIONID$/i,
  /^PHPSESSID$/i,
  /^ASP\.NET_SessionId$/i,
  /^_session$/i,
  /^laravel_session$/i,
  /^__Secure-/i,
  /^__Host-/i,
];

/** Check if a cookie name matches a session/auth pattern */
export function isSessionLikeCookie(name: string): boolean {
  return SESSION_COOKIE_PATTERNS.some(p => p.test(name));
}

/** Security headers to check */
export interface SecurityHeaderRule {
  /** Header name */
  header: string;
  /** Whether the header is required */
  required: boolean;
  /** Description of the header's purpose */
  description: string;
  /** Function to assess the header value */
  assess: (value: string | undefined) => { assessment: 'good' | 'warning' | 'missing' | 'misconfigured'; detail: string };
}

export const SECURITY_HEADER_RULES: SecurityHeaderRule[] = [
  {
    header: 'Content-Security-Policy',
    required: false,
    description: 'Prevents XSS and data injection attacks',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'CSP header not set. Consider implementing a Content Security Policy.' };
      if (value.includes("'unsafe-inline'") && value.includes("'unsafe-eval'")) {
        return { assessment: 'warning', detail: 'CSP allows unsafe-inline and unsafe-eval, reducing its effectiveness.' };
      }
      if (value.includes("'unsafe-inline'")) {
        return { assessment: 'warning', detail: 'CSP allows unsafe-inline, which weakens script protection.' };
      }
      return { assessment: 'good', detail: 'CSP header is present.' };
    },
  },
  {
    header: 'Strict-Transport-Security',
    required: false,
    description: 'Enforces HTTPS connections',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'HSTS header not set. HTTPS connections are not enforced via HSTS.' };
      const maxAgeMatch = value.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1], 10);
        if (maxAge < 31536000) {
          return { assessment: 'warning', detail: `HSTS max-age is ${maxAge}s (less than 1 year recommended).` };
        }
      }
      return { assessment: 'good', detail: 'HSTS header is properly configured.' };
    },
  },
  {
    header: 'X-Content-Type-Options',
    required: false,
    description: 'Prevents MIME-type sniffing',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'X-Content-Type-Options header not set.' };
      if (value.toLowerCase() !== 'nosniff') {
        return { assessment: 'misconfigured', detail: `Expected "nosniff" but got "${value}".` };
      }
      return { assessment: 'good', detail: 'X-Content-Type-Options is properly set to nosniff.' };
    },
  },
  {
    header: 'X-Frame-Options',
    required: false,
    description: 'Prevents clickjacking',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'X-Frame-Options header not set.' };
      const val = value.toUpperCase();
      if (val !== 'DENY' && val !== 'SAMEORIGIN') {
        return { assessment: 'warning', detail: `Unusual X-Frame-Options value: "${value}".` };
      }
      return { assessment: 'good', detail: 'X-Frame-Options is properly configured.' };
    },
  },
  {
    header: 'Referrer-Policy',
    required: false,
    description: 'Controls referrer information',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'Referrer-Policy header not set.' };
      const risky = ['unsafe-url', 'no-referrer-when-downgrade'];
      if (risky.includes(value.toLowerCase())) {
        return { assessment: 'warning', detail: `Referrer-Policy "${value}" may leak URL information.` };
      }
      return { assessment: 'good', detail: 'Referrer-Policy is properly configured.' };
    },
  },
  {
    header: 'Permissions-Policy',
    required: false,
    description: 'Controls browser features',
    assess: (value) => {
      if (!value) return { assessment: 'missing', detail: 'Permissions-Policy header not set.' };
      return { assessment: 'good', detail: 'Permissions-Policy header is present.' };
    },
  },
];

/** Storage keys that may contain sensitive data */
export const SENSITIVE_STORAGE_PATTERNS: { pattern: RegExp; classification: string }[] = [
  { pattern: /access.?token/i, classification: 'access_token' },
  { pattern: /refresh.?token/i, classification: 'refresh_token' },
  { pattern: /auth.?token/i, classification: 'auth_token' },
  { pattern: /jwt/i, classification: 'jwt' },
  { pattern: /api.?key/i, classification: 'api_key' },
  { pattern: /secret/i, classification: 'secret' },
  { pattern: /password/i, classification: 'password' },
  { pattern: /session/i, classification: 'session' },
  { pattern: /\brole\b/i, classification: 'role' },
  { pattern: /permission/i, classification: 'permissions' },
  { pattern: /\buser\b/i, classification: 'user_data' },
  { pattern: /credential/i, classification: 'credential' },
  { pattern: /\bauth\b/i, classification: 'auth_state' },
  { pattern: /config/i, classification: 'configuration' },
];
