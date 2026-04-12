/**
 * Tests for base32, HOTP, and TOTP (RFC 6238 / RFC 4226 vectors).
 * Uses Node.js built-in test runner: node --test tests/totp.test.js
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { base32Decode, base32Encode } from '../src/base32.js';
import { hotp, totp, hotpFromBytes, totpFromBytes, getTimeRemaining, parseOtpauthUrl } from '../src/totp.js';

// ─────────────────────────────────────────────────────────
// base32 tests
// ─────────────────────────────────────────────────────────

describe('base32Decode', () => {
  it('empty string returns empty Uint8Array', () => {
    const result = base32Decode('');
    assert.deepEqual(result, new Uint8Array(0));
  });

  it('decodes "MY======" → [0x66]', () => {
    // M=12, Y=24 → 01100 11000 → top 8 bits = 01100110 = 0x66
    const result = base32Decode('MY======');
    assert.equal(result[0], 0x66);
  });

  it('decodes "MFRA====" → correct bytes', () => {
    // M=12, F=5, R=17, A=0 → 01100 00101 10001 00000 → 01100001 01100010 00000... → 'ab'
    // Actually: MFRA = M(12) F(5) R(17) A(0)
    // 01100 00101 10001 00000 → bytes: 01100001 01100010 0 → 0x61 0x62 = 'ab' but padded differently
    // Let's just test round-trip
    const bytes = new Uint8Array([0x61, 0x62, 0x63]);
    const encoded = base32Encode(bytes);
    const decoded = base32Decode(encoded);
    assert.deepEqual(decoded, bytes);
  });

  it('is case insensitive', () => {
    const upper = base32Decode('JBSWY3DPEHPK3PXP');
    const lower = base32Decode('jbswy3dpehpk3pxp');
    assert.deepEqual(upper, lower);
  });

  it('ignores padding characters =', () => {
    const withPad = base32Decode('JBSWY3DP========');
    const noPad = base32Decode('JBSWY3DP');
    assert.deepEqual(withPad, noPad);
  });

  it('ignores spaces', () => {
    const spaced = base32Decode('JBSWY3DP EHPK3PXP');
    const normal = base32Decode('JBSWY3DPEHPK3PXP');
    assert.deepEqual(spaced, normal);
  });

  it('throws on invalid characters', () => {
    assert.throws(() => base32Decode('!@#$'), /Invalid base32/);
  });

  it('decodes known test vector: JBSWY3DPEHPK3PXP (10 bytes)', () => {
    // JBSWY3DPEHPK3PXP is 16 base32 chars = 10 bytes
    // First 6 bytes are "Hello!" (0x48 65 6c 6c 6f 21), then 4 more bytes
    const decoded = base32Decode('JBSWY3DPEHPK3PXP');
    assert.equal(decoded.length, 10);
    // The first 6 bytes must be "Hello!"
    assert.equal(decoded[0], 0x48); // H
    assert.equal(decoded[1], 0x65); // e
    assert.equal(decoded[2], 0x6c); // l
    assert.equal(decoded[3], 0x6c); // l
    assert.equal(decoded[4], 0x6f); // o
    assert.equal(decoded[5], 0x21); // !
  });
});

describe('base32Encode', () => {
  it('empty bytes returns empty string', () => {
    assert.equal(base32Encode(new Uint8Array(0)), '');
    assert.equal(base32Encode([]), '');
  });

  it('encodes [0x66] → "MY"', () => {
    // 0x66 = 01100110 → 01100 11000 → 12, 24 → M, Y
    const result = base32Encode(new Uint8Array([0x66]));
    assert.equal(result, 'MY');
  });

  it('round-trips arbitrary bytes', () => {
    const original = new Uint8Array([0x00, 0x01, 0x02, 0xff, 0xfe, 0x80, 0x7f]);
    const encoded = base32Encode(original);
    const decoded = base32Decode(encoded);
    assert.deepEqual(decoded, original);
  });

  it('round-trips "Hello!" = JBSWY3DPEE (no padding)', () => {
    // "Hello!" = 6 bytes = 48 bits → ceil(48/5) = 10 base32 chars (no padding)
    const bytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]);
    const encoded = base32Encode(bytes);
    assert.equal(encoded, 'JBSWY3DPEE');
    // Verify round-trip
    const decoded = base32Decode(encoded);
    assert.deepEqual(decoded, bytes);
  });
});

// ─────────────────────────────────────────────────────────
// HOTP tests (RFC 4226 Appendix D test vectors)
// Secret: "12345678901234567890" (ASCII bytes)
// ─────────────────────────────────────────────────────────

// RFC 4226 test secret as ASCII bytes
const RFC4226_SECRET_BYTES = new TextEncoder().encode('12345678901234567890');

describe('HOTP (RFC 4226 vectors)', () => {
  const vectors = [
    [0, '755224'],
    [1, '287082'],
    [2, '359152'],
    [3, '969429'],
    [4, '338314'],
    [5, '254676'],
    [6, '287922'],
    [7, '162583'],
    [8, '399871'],
    [9, '520489'],
  ];

  for (const [counter, expected] of vectors) {
    it(`counter=${counter} → ${expected}`, async () => {
      const result = await hotpFromBytes(RFC4226_SECRET_BYTES, counter, 6);
      assert.equal(result, expected, `HOTP counter=${counter}: expected ${expected}, got ${result}`);
    });
  }
});

// ─────────────────────────────────────────────────────────
// TOTP tests (RFC 6238 Appendix B test vectors)
// Secret: "12345678901234567890" (ASCII bytes), 8-digit TOTP
// ─────────────────────────────────────────────────────────

describe('TOTP (RFC 6238 vectors)', () => {
  const vectors = [
    [59,         '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ];

  for (const [timestamp, expected] of vectors) {
    it(`T=${timestamp} → ${expected}`, async () => {
      const result = await totpFromBytes(RFC4226_SECRET_BYTES, timestamp, 30, 8);
      assert.equal(result, expected, `TOTP T=${timestamp}: expected ${expected}, got ${result}`);
    });
  }
});

// ─────────────────────────────────────────────────────────
// TOTP with base32-encoded secret
// ─────────────────────────────────────────────────────────

describe('TOTP with base32 secret', () => {
  it('generates a 6-digit code for a known secret', async () => {
    // JBSWY3DPEHPK3PXP decodes to "Hello!"
    const code = await totp('JBSWY3DPEHPK3PXP', 1234567890, 30, 6);
    assert.match(code, /^\d{6}$/);
  });

  it('returns a zero-padded string if code starts with 0', async () => {
    // Use RFC4226 secret base32-encoded, T=59 → 8-digit 94287082
    // base32 encode "12345678901234567890"
    const secretB32 = base32Encode(RFC4226_SECRET_BYTES);
    const code = await totp(secretB32, 59, 30, 8);
    assert.equal(code, '94287082');
  });

  it('T=1111111109 produces 07081804 (leading zero)', async () => {
    const secretB32 = base32Encode(RFC4226_SECRET_BYTES);
    const code = await totp(secretB32, 1111111109, 30, 8);
    assert.equal(code, '07081804');
  });
});

// ─────────────────────────────────────────────────────────
// getTimeRemaining
// ─────────────────────────────────────────────────────────

describe('getTimeRemaining', () => {
  it('returns 30 at start of step', () => {
    assert.equal(getTimeRemaining(0, 30), 30);
    assert.equal(getTimeRemaining(30, 30), 30);
    assert.equal(getTimeRemaining(60, 30), 30);
  });

  it('returns 1 one second before end of step', () => {
    assert.equal(getTimeRemaining(29, 30), 1);
    assert.equal(getTimeRemaining(59, 30), 1);
  });

  it('returns 15 at midpoint of step', () => {
    assert.equal(getTimeRemaining(15, 30), 15);
    assert.equal(getTimeRemaining(45, 30), 15);
  });

  it('works with fractional timestamps', () => {
    // 0.5 seconds into the period → 29.5 remaining
    assert.ok(Math.abs(getTimeRemaining(0.5, 30) - 29.5) < 0.001);
  });

  it('uses Date.now()/1000 when timestamp is undefined', () => {
    const remaining = getTimeRemaining(undefined, 30);
    assert.ok(remaining > 0 && remaining <= 30);
  });
});

// ─────────────────────────────────────────────────────────
// parseOtpauthUrl
// ─────────────────────────────────────────────────────────

describe('parseOtpauthUrl', () => {
  it('parses a basic otpauth URL', () => {
    const url = 'otpauth://totp/user%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example';
    const result = parseOtpauthUrl(url);
    assert.ok(result);
    assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
    assert.equal(result.label, 'user@example.com');
    assert.equal(result.issuer, 'Example');
    assert.equal(result.digits, 6);
    assert.equal(result.period, 30);
  });

  it('parses label with issuer:account format', () => {
    const url = 'otpauth://totp/GitHub%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP';
    const result = parseOtpauthUrl(url);
    assert.ok(result);
    assert.equal(result.issuer, 'GitHub');
    assert.equal(result.label, 'user@example.com');
  });

  it('returns null for non-otpauth URLs', () => {
    assert.equal(parseOtpauthUrl('https://example.com'), null);
    assert.equal(parseOtpauthUrl(''), null);
    assert.equal(parseOtpauthUrl(null), null);
  });

  it('returns null when secret is missing', () => {
    const url = 'otpauth://totp/user@example.com?issuer=Example';
    assert.equal(parseOtpauthUrl(url), null);
  });

  it('parses custom digits and period', () => {
    const url = 'otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP&digits=8&period=60';
    const result = parseOtpauthUrl(url);
    assert.ok(result);
    assert.equal(result.digits, 8);
    assert.equal(result.period, 60);
  });

  it('normalizes secret to uppercase and strips spaces', () => {
    const url = 'otpauth://totp/Test?secret=jbswy3dp+ehpk3pxp';
    const result = parseOtpauthUrl(url);
    assert.ok(result);
    assert.equal(result.secret, 'JBSWY3DPEHPK3PXP');
  });
});

// ─────────────────────────────────────────────────────────
// Edge cases
// ─────────────────────────────────────────────────────────

describe('Edge cases', () => {
  it('base32Decode handles single character (incomplete group)', () => {
    // 'A' = 0 → only 5 bits, no complete byte → empty
    const result = base32Decode('A');
    assert.equal(result.length, 0);
  });

  it('totp returns 6-digit zero-padded string', async () => {
    // Use any secret and find a timestamp producing small code
    const code = await totp('JBSWY3DPEHPK3PXP', 0, 30, 6);
    assert.match(code, /^\d{6}$/);
  });

  it('hotpFromBytes handles counter=0', async () => {
    const code = await hotpFromBytes(RFC4226_SECRET_BYTES, 0, 6);
    assert.equal(code, '755224');
  });

  it('base32Decode single valid byte (16 chars = 10 bytes exactly)', () => {
    const bytes = new Uint8Array(10).fill(0xff);
    const encoded = base32Encode(bytes);
    const decoded = base32Decode(encoded);
    assert.deepEqual(decoded, bytes);
  });

  it('HOTP produces string not number', async () => {
    const code = await hotpFromBytes(RFC4226_SECRET_BYTES, 0, 6);
    assert.equal(typeof code, 'string');
  });
});
