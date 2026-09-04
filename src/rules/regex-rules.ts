/**
 * @module regex-rules
 * Named regex patterns for detecting sensitive data.
 * Each rule includes a name, pattern, description, and validation function.
 */

export interface RegexRule {
  /** Rule name identifier */
  name: string;
  /** The regex pattern (global flag applied during scanning) */
  pattern: RegExp;
  /** Human-readable description */
  description: string;
  /** Optional validation function to reduce false positives */
  validate?: (match: string) => boolean;
  /** Sensitive type for redaction */
  sensitiveType: string;
}

/**
 * Luhn algorithm validation for credit card numbers.
 * @param digits - String of digits to validate
 * @returns true if the digits pass Luhn check
 */
export function luhnCheck(digits: string): boolean {
  const nums = digits.replace(/\D/g, '');
  if (nums.length < 13 || nums.length > 19) return false;

  let sum = 0;
  let isEven = false;

  for (let i = nums.length - 1; i >= 0; i--) {
    let digit = parseInt(nums[i], 10);

    if (isEven) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    isEven = !isEven;
  }

  return sum % 10 === 0;
}

/** All regex rules for sensitive data detection */
export const REGEX_RULES: RegexRule[] = [
  {
    name: 'email',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    description: 'Email address',
    sensitiveType: 'email',
  },
  {
    name: 'us_phone',
    pattern: /(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g,
    description: 'US phone number',
    validate: (match: string) => {
      const digits = match.replace(/\D/g, '');
      return digits.length >= 10 && digits.length <= 11;
    },
    sensitiveType: 'phone',
  },
  {
    name: 'us_ssn',
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    description: 'US Social Security Number',
    validate: (match: string) => {
      const parts = match.split('-');
      const area = parseInt(parts[0], 10);
      // SSNs cannot start with 000, 666, or 900-999
      return area !== 0 && area !== 666 && area < 900;
    },
    sensitiveType: 'ssn',
  },
  {
    name: 'credit_card',
    pattern: /\b(?:\d{4}[-\s]?){3}\d{1,4}\b/g,
    description: 'Credit card number',
    validate: (match: string) => luhnCheck(match),
    sensitiveType: 'credit_card',
  },
  {
    name: 'jwt',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    description: 'JSON Web Token',
    sensitiveType: 'jwt',
  },
  {
    name: 'aws_access_key',
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,
    description: 'AWS Access Key ID',
    sensitiveType: 'aws_key',
  },
  {
    name: 'private_key',
    pattern: /-----BEGIN\s(?:RSA|EC|OPENSSH|DSA|PGP)?\s?PRIVATE\sKEY-----/g,
    description: 'Private key header',
    sensitiveType: 'private_key',
  },
  {
    name: 'internal_ipv4',
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    description: 'Internal/private IPv4 address (RFC 1918)',
    sensitiveType: 'ip_address',
  },
  {
    name: 'mongodb_connection',
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>]{5,}/g,
    description: 'MongoDB connection string',
    sensitiveType: 'db_connection',
  },
  {
    name: 'mysql_connection',
    pattern: /mysql:\/\/[^\s"'<>]{5,}/g,
    description: 'MySQL connection string',
    sensitiveType: 'db_connection',
  },
  {
    name: 'postgresql_connection',
    pattern: /postgres(?:ql)?:\/\/[^\s"'<>]{5,}/g,
    description: 'PostgreSQL connection string',
    sensitiveType: 'db_connection',
  },
  {
    name: 'uuid',
    pattern: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
    description: 'UUID',
    sensitiveType: 'uuid',
  },
  {
    name: 'mongodb_objectid',
    pattern: /\b[0-9a-fA-F]{24}\b/g,
    description: 'MongoDB ObjectId',
    validate: (match: string) => {
      // Must be exactly 24 hex chars and not a substring of a longer hex string
      return /^[0-9a-fA-F]{24}$/.test(match);
    },
    sensitiveType: 'generic',
  },
  {
    name: 'api_key_param',
    pattern: /[?&](?:api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token)=([^&\s"']{8,})/gi,
    description: 'API key in URL parameter',
    sensitiveType: 'api_key',
  },
  {
    name: 'bearer_token',
    pattern: /Bearer\s+[A-Za-z0-9_-]{20,}/g,
    description: 'Bearer authentication token',
    sensitiveType: 'bearer_token',
  },
  {
    name: 'basic_auth',
    pattern: /Basic\s+[A-Za-z0-9+/=]{10,}/g,
    description: 'Basic authentication value',
    sensitiveType: 'basic_auth',
  },
  {
    name: 'private_ipv6',
    pattern: /\b(?:fc|fd)[0-9a-fA-F]{2}(?::[0-9a-fA-F]{1,4}){1,7}\b/g,
    description: 'Private IPv6 address (ULA)',
    sensitiveType: 'ip_address',
  },
];
