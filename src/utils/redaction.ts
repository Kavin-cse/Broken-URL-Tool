/**
 * @module redaction
 * Configurable sensitive value masking.
 * 
 * Three modes:
 * - SAFE: heavily masked, minimal exposure
 * - BALANCED: partial masking showing type indicators
 * - FORENSIC: minimal masking (explicit opt-in only)
 */

export enum RedactionMode {
  SAFE = 'safe',
  BALANCED = 'balanced',
  FORENSIC = 'forensic',
}

export type SensitiveType =
  | 'email'
  | 'phone'
  | 'ssn'
  | 'credit_card'
  | 'jwt'
  | 'aws_key'
  | 'private_key'
  | 'api_key'
  | 'bearer_token'
  | 'basic_auth'
  | 'password'
  | 'session_id'
  | 'cookie'
  | 'ip_address'
  | 'db_connection'
  | 'uuid'
  | 'generic';

let globalMode: RedactionMode = RedactionMode.SAFE;

/** Set the global redaction mode */
export function setRedactionMode(mode: RedactionMode): void {
  globalMode = mode;
}

/** Get the current redaction mode */
export function getRedactionMode(): RedactionMode {
  return globalMode;
}

/**
 * Mask a sensitive value according to its type and the current redaction mode.
 * @param value - The raw sensitive value
 * @param type - The type of sensitive data
 * @param mode - Override the global mode for this call
 * @returns The masked value
 */
export function maskSensitiveValue(
  value: string,
  type: SensitiveType = 'generic',
  mode?: RedactionMode
): string {
  const effectiveMode = mode ?? globalMode;

  if (!value || value.length === 0) {
    return '[EMPTY]';
  }

  switch (effectiveMode) {
    case RedactionMode.FORENSIC:
      return maskForensic(value, type);
    case RedactionMode.BALANCED:
      return maskBalanced(value, type);
    case RedactionMode.SAFE:
    default:
      return maskSafe(value, type);
  }
}

/** SAFE mode: heavy masking */
function maskSafe(value: string, type: SensitiveType): string {
  switch (type) {
    case 'email': {
      const atIndex = value.indexOf('@');
      if (atIndex > 0) {
        const domain = value.substring(atIndex);
        return `${value[0]}***${domain}`;
      }
      return '***@***';
    }
    case 'phone':
      return '***-***-' + value.slice(-4);
    case 'ssn':
      return '***-**-' + value.slice(-4);
    case 'credit_card':
      return '************' + value.replace(/\D/g, '').slice(-4);
    case 'jwt':
      return 'eyJ...REDACTED';
    case 'aws_key':
      return value.substring(0, 4) + '...REDACTED';
    case 'private_key':
      if (value.includes('BEGIN')) {
        const match = value.match(/(-----BEGIN [A-Z\s]+ KEY-----)/);
        return match ? `${match[1]} [REDACTED]` : '[PRIVATE KEY REDACTED]';
      }
      return '[PRIVATE KEY REDACTED]';
    case 'api_key':
      return value.substring(0, 4) + '...REDACTED';
    case 'bearer_token':
      return 'Bearer ...REDACTED';
    case 'basic_auth':
      return 'Basic ...REDACTED';
    case 'password':
      return '***REDACTED***';
    case 'session_id':
      return value.substring(0, 4) + '...REDACTED';
    case 'cookie':
      return value.substring(0, 3) + '...REDACTED';
    case 'ip_address':
      return value.replace(/\d+\.\d+$/, '*.*');
    case 'db_connection':
      // Mask credentials in connection strings
      return value.replace(/\/\/[^@]+@/, '//***:***@');
    case 'uuid':
      return value.substring(0, 8) + '-****-****-****-************';
    case 'generic':
    default:
      if (value.length <= 4) return '***';
      return value.substring(0, 2) + '***' + value.slice(-2);
  }
}

/** BALANCED mode: partial masking */
function maskBalanced(value: string, type: SensitiveType): string {
  switch (type) {
    case 'email': {
      const atIndex = value.indexOf('@');
      if (atIndex > 0) {
        const local = value.substring(0, atIndex);
        const domain = value.substring(atIndex);
        const shown = Math.min(3, Math.floor(local.length / 2));
        return local.substring(0, shown) + '***' + domain;
      }
      return '***@***';
    }
    case 'phone':
      return '(' + value.replace(/\D/g, '').substring(0, 3) + ') ***-' + value.slice(-4);
    case 'ssn':
      return '***-**-' + value.slice(-4);
    case 'credit_card': {
      const digits = value.replace(/\D/g, '');
      return digits.substring(0, 4) + ' **** **** ' + digits.slice(-4);
    }
    case 'jwt': {
      const parts = value.split('.');
      if (parts.length >= 2) {
        return parts[0].substring(0, 20) + '...REDACTED';
      }
      return 'eyJ...REDACTED';
    }
    case 'aws_key':
      return value.substring(0, 8) + '...REDACTED';
    case 'private_key': {
      const match = value.match(/(-----BEGIN [A-Z\s]+ KEY-----)/);
      return match ? `${match[1]} [REDACTED]` : '[PRIVATE KEY REDACTED]';
    }
    case 'api_key':
      return value.substring(0, 8) + '...' + value.slice(-4);
    case 'bearer_token':
      return 'Bearer ' + value.replace(/^Bearer\s+/i, '').substring(0, 10) + '...REDACTED';
    case 'basic_auth':
      return 'Basic REDACTED';
    case 'password':
      return '***REDACTED***';
    case 'session_id':
      return value.substring(0, 8) + '...' + value.slice(-4);
    case 'cookie':
      return value.substring(0, 6) + '...' + value.slice(-4);
    case 'ip_address':
      return value;
    case 'db_connection':
      return value.replace(/\/\/[^@]+@/, '//***:***@');
    case 'uuid':
      return value.substring(0, 13) + '-****-' + value.slice(-12);
    case 'generic':
    default:
      if (value.length <= 6) return value.substring(0, 2) + '***';
      const quarter = Math.floor(value.length / 4);
      return value.substring(0, quarter) + '***' + value.slice(-quarter);
  }
}

/** FORENSIC mode: minimal masking for authorized investigations */
function maskForensic(value: string, type: SensitiveType): string {
  // Even in forensic mode, we partially mask the most sensitive types
  switch (type) {
    case 'password':
      return '***REDACTED***';
    case 'private_key': {
      const match = value.match(/(-----BEGIN [A-Z\s]+ KEY-----)/);
      return match ? `${match[1]} [CONTENT AVAILABLE IN RAW DATA]` : '[PRIVATE KEY - SEE RAW DATA]';
    }
    case 'ssn': {
      const digits = value.replace(/\D/g, '');
      return digits.substring(0, 3) + '-' + digits.substring(3, 5) + '-' + digits.substring(5);
    }
    default:
      return value;
  }
}

/**
 * Map a regex rule name to its sensitive type for masking.
 */
export function ruleNameToSensitiveType(ruleName: string): SensitiveType {
  const map: Record<string, SensitiveType> = {
    email: 'email',
    us_phone: 'phone',
    us_ssn: 'ssn',
    credit_card: 'credit_card',
    jwt: 'jwt',
    aws_access_key: 'aws_key',
    private_key: 'private_key',
    internal_ipv4: 'ip_address',
    private_ipv6: 'ip_address',
    mongodb_connection: 'db_connection',
    mysql_connection: 'db_connection',
    postgresql_connection: 'db_connection',
    uuid: 'uuid',
    mongodb_objectid: 'generic',
    api_key_param: 'api_key',
    bearer_token: 'bearer_token',
    basic_auth: 'basic_auth',
  };
  return map[ruleName] || 'generic';
}
