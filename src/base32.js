/**
 * RFC 4648 Base32 encoder/decoder
 * Alphabet: ABCDEFGHIJKLMNOPQRSTUVWXYZ234567
 */

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const LOOKUP = new Map(
  [...ALPHABET].map((c, i) => [c, i])
);

/**
 * Decode a base32-encoded string to Uint8Array.
 * Ignores padding ('=') and whitespace. Case insensitive.
 * @param {string} input
 * @returns {Uint8Array}
 */
export function base32Decode(input) {
  if (!input) return new Uint8Array(0);

  // Normalize: uppercase, strip whitespace and padding
  const str = input.toUpperCase().replace(/[\s=]/g, '');

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of str) {
    const v = LOOKUP.get(char);
    if (v === undefined) {
      throw new Error(`Invalid base32 character: ${char}`);
    }
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Encode a Uint8Array (or array of bytes) to a base32 string (no padding).
 * @param {Uint8Array|number[]} bytes
 * @returns {string}
 */
export function base32Encode(bytes) {
  if (!bytes || bytes.length === 0) return '';

  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return output;
}
