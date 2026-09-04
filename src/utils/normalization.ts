/**
 * @module normalization
 * Value normalization for deduplication and comparison.
 */

/**
 * Normalize an email address for deduplication.
 * Lowercases the entire address.
 */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

/**
 * Normalize a UUID for deduplication.
 * Lowercases and removes hyphens.
 */
export function normalizeUUID(uuid: string): string {
  return uuid.trim().toLowerCase().replace(/-/g, '');
}

/**
 * Normalize a credit card number for deduplication.
 * Removes all non-digit characters.
 */
export function normalizeCreditCard(cc: string): string {
  return cc.replace(/\D/g, '');
}

/**
 * Normalize whitespace in a string.
 * Collapses multiple whitespace to single space, trims.
 */
export function normalizeWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Normalize a URL for comparison.
 * Lowercases scheme and host, removes trailing slash, sorts query params.
 */
export function normalizeUrl(urlStr: string): string {
  try {
    const url = new URL(urlStr);
    url.searchParams.sort();
    let normalized = `${url.protocol}//${url.host}${url.pathname}`;
    if (url.search) {
      normalized += url.search;
    }
    // Remove trailing slash
    normalized = normalized.replace(/\/$/, '');
    return normalized.toLowerCase();
  } catch {
    return urlStr.trim().toLowerCase();
  }
}

/**
 * Normalize a phone number for deduplication.
 * Strips to digits only.
 */
export function normalizePhone(phone: string): string {
  return phone.replace(/\D/g, '');
}

/**
 * Normalize an SSN for deduplication.
 * Strips to digits only.
 */
export function normalizeSSN(ssn: string): string {
  return ssn.replace(/\D/g, '');
}

/**
 * Normalize a matched value based on its rule type.
 */
export function normalizeByRule(value: string, ruleName: string): string {
  switch (ruleName) {
    case 'email':
      return normalizeEmail(value);
    case 'uuid':
      return normalizeUUID(value);
    case 'credit_card':
      return normalizeCreditCard(value);
    case 'us_phone':
      return normalizePhone(value);
    case 'us_ssn':
      return normalizeSSN(value);
    default:
      return normalizeWhitespace(value);
  }
}
