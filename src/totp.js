/**
 * TOTP / HOTP implementation per RFC 6238 / RFC 4226.
 * Uses Web Crypto API in browser; falls back to node:crypto in Node.js.
 */

import { base32Decode } from './base32.js';

/**
 * Compute HMAC-SHA1.
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} dataBytes
 * @returns {Promise<Uint8Array>}
 */
async function hmacSha1(keyBytes, dataBytes) {
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, dataBytes);
    return new Uint8Array(sig);
  }
  // Node.js fallback
  const { createHmac } = await import('node:crypto');
  return new Uint8Array(createHmac('sha1', Buffer.from(keyBytes)).update(Buffer.from(dataBytes)).digest());
}

/**
 * Convert a counter (integer or BigInt) to an 8-byte big-endian Uint8Array.
 * @param {number|bigint} counter
 * @returns {Uint8Array}
 */
function counterToBytes(counter) {
  const buf = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  return buf;
}

/**
 * HOTP (RFC 4226).
 * @param {Uint8Array} secretBytes - raw secret bytes (already decoded from base32)
 * @param {number|bigint} counter - 8-byte counter value
 * @param {number} [digits=6]
 * @returns {Promise<string>} zero-padded digit string
 */
export async function hotpFromBytes(secretBytes, counter, digits = 6) {
  const counterBytes = counterToBytes(counter);
  const hash = await hmacSha1(secretBytes, counterBytes);

  // Dynamic truncation
  const offset = hash[19] & 0x0f;
  const code =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = code % Math.pow(10, digits);
  return String(otp).padStart(digits, '0');
}

/**
 * HOTP with base32-encoded secret.
 * @param {string} secret - base32-encoded secret
 * @param {number|bigint} counter
 * @param {number} [digits=6]
 * @returns {Promise<string>}
 */
export async function hotp(secret, counter, digits = 6) {
  const secretBytes = base32Decode(secret);
  return hotpFromBytes(secretBytes, counter, digits);
}

/**
 * TOTP (RFC 6238).
 * @param {string} secret - base32-encoded secret
 * @param {number} [timestamp=Date.now()/1000] - Unix timestamp in seconds
 * @param {number} [step=30] - time step in seconds
 * @param {number} [digits=6]
 * @returns {Promise<string>}
 */
export async function totp(secret, timestamp, step = 30, digits = 6) {
  if (timestamp === undefined) {
    timestamp = Math.floor(Date.now() / 1000);
  }
  const counter = Math.floor(timestamp / step);
  return hotp(secret, counter, digits);
}

/**
 * TOTP with raw secret bytes (used for RFC 6238 test vectors which use ASCII bytes directly).
 * @param {Uint8Array} secretBytes
 * @param {number} timestamp
 * @param {number} [step=30]
 * @param {number} [digits=8]
 * @returns {Promise<string>}
 */
export async function totpFromBytes(secretBytes, timestamp, step = 30, digits = 8) {
  const counter = Math.floor(timestamp / step);
  return hotpFromBytes(secretBytes, counter, digits);
}

/**
 * Returns seconds until the next TOTP refresh.
 * @param {number} [timestamp=Date.now()/1000]
 * @param {number} [step=30]
 * @returns {number}
 */
export function getTimeRemaining(timestamp, step = 30) {
  if (timestamp === undefined) {
    timestamp = Date.now() / 1000;
  }
  return step - (timestamp % step);
}

/**
 * Parse an otpauth:// URL.
 * Format: otpauth://totp/LABEL?secret=SECRET&issuer=ISSUER&digits=6&period=30&algorithm=SHA1
 * @param {string} url
 * @returns {{ label: string, issuer: string, secret: string, digits: number, period: number, algorithm: string } | null}
 */
export function parseOtpauthUrl(url) {
  if (!url || !url.startsWith('otpauth://')) return null;

  try {
    const u = new URL(url);
    if (u.protocol !== 'otpauth:') return null;
    if (u.hostname !== 'totp' && u.hostname !== 'hotp') return null;

    // Label is the pathname (starts with /)
    const rawLabel = decodeURIComponent(u.pathname.slice(1));
    const params = u.searchParams;

    const secret = params.get('secret');
    if (!secret) return null;

    const issuer = params.get('issuer') || '';
    const digits = parseInt(params.get('digits') || '6', 10);
    const period = parseInt(params.get('period') || '30', 10);
    const algorithm = (params.get('algorithm') || 'SHA1').toUpperCase();

    // Label may have "issuer:account" format
    let label = rawLabel;
    let accountIssuer = issuer;
    if (rawLabel.includes(':')) {
      const [issPart, accPart] = rawLabel.split(':', 2);
      accountIssuer = accountIssuer || issPart;
      label = accPart;
    }

    return {
      label,
      issuer: accountIssuer,
      secret: secret.toUpperCase().replace(/\s/g, ''),
      digits,
      period,
      algorithm,
    };
  } catch {
    return null;
  }
}
