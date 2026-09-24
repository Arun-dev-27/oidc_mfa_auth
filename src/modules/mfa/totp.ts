import { createHmac } from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/g, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32.indexOf(ch);
    if (idx < 0) throw new Error('invalid base32 secret');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

/** RFC 4226 HOTP, SHA-1, 6 digits (what authenticator apps use). */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * RFC 6238 TOTP check with a +/- `window` step tolerance. Returns the matching time step (so the
 * caller can reject its reuse), or null.
 */
export function verifyTotp(secretBase32: string, code: string, nowMs = Date.now(), window = 1, stepSeconds = 30): number | null {
  if (!/^[0-9]{6}$/.test(code)) return null;
  const secret = base32Decode(secretBase32);
  const current = Math.floor(nowMs / 1000 / stepSeconds);
  for (let delta = -window; delta <= window; delta++) {
    const step = current + delta;
    if (hotp(secret, step) === code) return step;
  }
  return null;
}
