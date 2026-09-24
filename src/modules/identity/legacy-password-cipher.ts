import { randomInt } from 'node:crypto';
import * as iconv from 'iconv-lite';

/**
 * Legacy reversible password cipher used for users.password.
 *
 * decrypt() is a byte-for-byte port of the production C# `Decrypt(string)` (same implementation as
 * core-authentication, validated there against the stage database):
 *
 *   public string Decrypt(string passwordString)
 *   {
 *       if (string.IsNullOrEmpty(passwordString) || passwordString.Length % 2 != 0) return string.Empty;
 *       int halfLength = passwordString.Length / 2;
 *       // first half = dpass, second half = rnumbers, both read as Windows-1252 bytes
 *       result[i] = (char)(255 - (dpassChar + rnumberChar));
 *   }
 *
 * encrypt() is its exact inverse: for every plaintext byte p it picks a random key byte r and stores
 * d = 255 - p - r, output = d-chars + r-chars. Both halves are printable ASCII (33..126), which is
 * what the stored passwords look like, so the ciphertext survives any varchar / encoding round trip.
 *
 * Load-bearing details: Windows-1252 byte per char (iconv 'win1252'); empty/odd input -> '';
 * C# (char) of a negative int wraps modulo 65536.
 *
 * Plaintext passwords are only ever compared or encrypted in memory; never logged or stored.
 */
export function decrypt(passwordString: string | null | undefined): string {
  if (!passwordString || passwordString.length % 2 !== 0) return '';

  const half = passwordString.length / 2;
  const dpass = passwordString.slice(0, half);
  const rnumbers = passwordString.slice(half);

  let result = '';
  for (let i = 0; i < half; i++) {
    const d = iconv.encode(dpass[i], 'win1252')[0];
    const r = iconv.encode(rnumbers[i], 'win1252')[0];
    const raw = 255 - (d + r);
    result += String.fromCharCode(((raw % 65536) + 65536) % 65536);
  }
  return result;
}

const MIN = 33; // '!'
const MAX = 126; // '~'

/**
 * Produces a ciphertext that the legacy Decrypt() turns back into `plaintext`.
 * Supports characters whose Windows-1252 byte is 3..189 (all printable ASCII included); anything
 * else cannot be represented with printable key characters and is refused.
 */
export function encrypt(plaintext: string): string {
  if (!plaintext) throw new Error('password must not be empty');
  let dpass = '';
  let rnumbers = '';
  for (const ch of plaintext) {
    const bytes = iconv.encode(ch, 'win1252');
    const p = bytes[0];
    if (bytes.length !== 1 || iconv.decode(bytes, 'win1252') !== ch) throw new Error('password contains a character the legacy format cannot store');
    const sum = 255 - p; // d + r
    const low = Math.max(MIN, sum - MAX);
    const high = Math.min(MAX, sum - MIN);
    if (low > high) throw new Error('password contains a character the legacy format cannot store');
    const r = randomInt(low, high + 1);
    dpass += String.fromCharCode(sum - r);
    rnumbers += String.fromCharCode(r);
  }
  const cipher = dpass + rnumbers;
  if (decrypt(cipher) !== plaintext) throw new Error('legacy encryption self-check failed');
  return cipher;
}
