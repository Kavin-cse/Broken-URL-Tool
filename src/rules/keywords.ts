/**
 * @module keywords
 * Security-relevant keyword dictionary for text scanning.
 * Keywords are case-insensitive and categorized by type.
 */

export interface KeywordEntry {
  /** The keyword to search for */
  keyword: string;
  /** Category for grouping */
  category: string;
  /** Weight for risk scoring (higher = more significant) */
  weight: number;
}

/** All security-relevant keywords grouped by category */
export const KEYWORD_DICTIONARY: KeywordEntry[] = [
  // Authentication & Authorization
  { keyword: 'password', category: 'credentials', weight: 8 },
  { keyword: 'passwd', category: 'credentials', weight: 8 },
  { keyword: 'credential', category: 'credentials', weight: 7 },
  { keyword: 'credentials', category: 'credentials', weight: 7 },
  { keyword: 'authorization', category: 'auth', weight: 5 },
  { keyword: 'bearer', category: 'auth', weight: 6 },
  { keyword: 'access token', category: 'auth', weight: 7 },
  { keyword: 'refresh token', category: 'auth', weight: 7 },
  { keyword: 'client_secret', category: 'auth', weight: 8 },
  { keyword: 'client secret', category: 'auth', weight: 8 },
  { keyword: 'secret', category: 'auth', weight: 5 },
  { keyword: 'token', category: 'auth', weight: 4 },
  { keyword: 'apikey', category: 'auth', weight: 7 },
  { keyword: 'api_key', category: 'auth', weight: 7 },
  { keyword: 'private_key', category: 'auth', weight: 8 },

  // Roles & Permissions
  { keyword: 'admin', category: 'roles', weight: 5 },
  { keyword: 'administrator', category: 'roles', weight: 5 },
  { keyword: 'root', category: 'roles', weight: 5 },
  { keyword: 'superuser', category: 'roles', weight: 6 },
  { keyword: 'manager', category: 'roles', weight: 3 },
  { keyword: 'director', category: 'roles', weight: 3 },
  { keyword: 'executive', category: 'roles', weight: 3 },

  // PII & HR Data
  { keyword: 'ssn', category: 'pii', weight: 9 },
  { keyword: 'social security', category: 'pii', weight: 9 },
  { keyword: 'passport', category: 'pii', weight: 8 },
  { keyword: 'driver_license', category: 'pii', weight: 8 },
  { keyword: 'driver licence', category: 'pii', weight: 8 },
  { keyword: 'medical', category: 'pii', weight: 6 },
  { keyword: 'medical record', category: 'pii', weight: 8 },
  { keyword: 'hipaa', category: 'pii', weight: 7 },
  { keyword: 'employee', category: 'pii', weight: 3 },
  { keyword: 'employees', category: 'pii', weight: 3 },
  { keyword: 'employee_id', category: 'pii', weight: 5 },
  { keyword: 'staff', category: 'pii', weight: 3 },
  { keyword: 'personal data', category: 'pii', weight: 6 },
  { keyword: 'pii', category: 'pii', weight: 6 },
  { keyword: 'phi', category: 'pii', weight: 7 },
  { keyword: 'customer data', category: 'pii', weight: 5 },

  // Financial
  { keyword: 'salary', category: 'financial', weight: 7 },
  { keyword: 'bonus', category: 'financial', weight: 6 },
  { keyword: 'payroll', category: 'financial', weight: 7 },
  { keyword: 'compensation', category: 'financial', weight: 6 },
  { keyword: 'bank_account', category: 'financial', weight: 8 },
  { keyword: 'routing_number', category: 'financial', weight: 8 },
  { keyword: 'revenue', category: 'financial', weight: 4 },
  { keyword: 'profit', category: 'financial', weight: 4 },
  { keyword: 'financial', category: 'financial', weight: 3 },
  { keyword: 'invoice', category: 'financial', weight: 4 },

  // HR & Corporate
  { keyword: 'termination', category: 'hr', weight: 5 },
  { keyword: 'terminated', category: 'hr', weight: 5 },
  { keyword: 'layoff', category: 'hr', weight: 5 },
  { keyword: 'hr', category: 'hr', weight: 3 },
  { keyword: 'human resources', category: 'hr', weight: 4 },
  { keyword: 'acquisition', category: 'corporate', weight: 4 },
  { keyword: 'merger', category: 'corporate', weight: 4 },

  // Classification
  { keyword: 'confidential', category: 'classification', weight: 6 },
  { keyword: 'classified', category: 'classification', weight: 7 },
  { keyword: 'topsecret', category: 'classification', weight: 9 },
  { keyword: 'top secret', category: 'classification', weight: 9 },
  { keyword: 'internal only', category: 'classification', weight: 6 },
  { keyword: 'do not distribute', category: 'classification', weight: 7 },
  { keyword: 'restricted', category: 'classification', weight: 5 },
  { keyword: 'sensitive', category: 'classification', weight: 4 },
  { keyword: 'private', category: 'classification', weight: 3 },
  { keyword: 'internal', category: 'classification', weight: 3 },

  // Infrastructure & Database
  { keyword: 'database', category: 'infrastructure', weight: 4 },
  { keyword: 'db_password', category: 'infrastructure', weight: 9 },
  { keyword: 'connection string', category: 'infrastructure', weight: 7 },
];

/** Route indicators that suggest admin/internal areas */
export const ROUTE_INDICATORS: { pattern: string; category: string; weight: number }[] = [
  { pattern: '/admin', category: 'admin', weight: 5 },
  { pattern: '/administrator', category: 'admin', weight: 5 },
  { pattern: '/dashboard', category: 'admin', weight: 4 },
  { pattern: '/internal', category: 'internal', weight: 5 },
  { pattern: '/private', category: 'internal', weight: 4 },
  { pattern: '/staff', category: 'internal', weight: 4 },
  { pattern: '/employee', category: 'internal', weight: 4 },
  { pattern: '/manager', category: 'admin', weight: 4 },
  { pattern: '/hr', category: 'internal', weight: 4 },
  { pattern: '/finance', category: 'internal', weight: 4 },
  { pattern: '/api/', category: 'api', weight: 3 },
  { pattern: '/graphql', category: 'api', weight: 4 },
  { pattern: '/debug', category: 'debug', weight: 6 },
  { pattern: '/management', category: 'admin', weight: 4 },
];

/** JSON field names that may indicate sensitive data */
export const SENSITIVE_JSON_FIELDS: string[] = [
  'email', 'phone', 'address', 'salary', 'compensation',
  'ssn', 'socialSecurityNumber', 'social_security_number',
  'employeeId', 'employee_id', 'customerId', 'customer_id',
  'userId', 'user_id', 'role', 'roles', 'permissions',
  'accessToken', 'access_token', 'refreshToken', 'refresh_token',
  'apiKey', 'api_key', 'secret', 'password', 'passwd',
  'bankAccount', 'bank_account', 'routingNumber', 'routing_number',
  'creditCard', 'credit_card', 'cardNumber', 'card_number',
  'dateOfBirth', 'date_of_birth', 'dob',
  'firstName', 'first_name', 'lastName', 'last_name',
  'fullName', 'full_name',
];

/** Suspicious source code comment patterns */
export const SUSPICIOUS_COMMENT_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /todo\s+security/i, reason: 'Security-related TODO' },
  { pattern: /fixme\s+security/i, reason: 'Security-related FIXME' },
  { pattern: /debug/i, reason: 'Debug reference' },
  { pattern: /temporary\s+auth/i, reason: 'Temporary authentication reference' },
  { pattern: /disable\s+auth/i, reason: 'Auth disabling reference' },
  { pattern: /bypass/i, reason: 'Bypass reference' },
  { pattern: /internal\s+only/i, reason: 'Internal-only marker' },
  { pattern: /secret/i, reason: 'Secret reference' },
  { pattern: /password/i, reason: 'Password reference' },
  { pattern: /hack/i, reason: 'Hack reference' },
  { pattern: /workaround/i, reason: 'Workaround reference' },
  { pattern: /hardcoded/i, reason: 'Hardcoded value reference' },
];
