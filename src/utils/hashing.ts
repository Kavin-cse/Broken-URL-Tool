/**
 * @module hashing
 * SHA-256 hashing for deduplication and cookie fingerprinting.
 */

import { createHash } from 'crypto';

/**
 * Compute SHA-256 hash of a string value.
 * @param value - The value to hash
 * @returns Hex-encoded SHA-256 hash
 */
export function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Compute a short hash (first 12 hex chars) for display purposes.
 * @param value - The value to hash
 * @returns Short hex hash
 */
export function shortHash(value: string): string {
  return sha256(value).substring(0, 12);
}
