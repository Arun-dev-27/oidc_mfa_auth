/**
 * Requested-path safety for trusted handoff (Handoff spec §18, SSO spec §33.2).
 *
 * Only a relative application path can be handed off - never a URL:
 *   allowed   /events/123   /bookings/ABC   /dashboard   /events/123?tab=seats
 *   refused   https://evil.example   //evil.example   \\evil.example   javascript:...
 *             /../admin   /%2e%2e/admin   /a/./b   control characters   anything over 512 chars
 * The path is normalized (percent-decoded once) before it is checked, and the result is matched
 * against the target's allowlist, where "*" stands for exactly one path segment.
 */

const MAX_LENGTH = 512;
const ALLOWED_CHARS = /^\/[A-Za-z0-9\-._~/%!$&'()*+,;=:@?]*$/;

/** Returns the normalized path, or null when it is not a safe relative path. */
export function normalizeRelativePath(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  // No trimming: a path that is not exactly a safe relative path is rejected, never repaired.
  const raw = input;
  if (!raw || raw.length > MAX_LENGTH) return null;
  if (!raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return null;
  if (!ALLOWED_CHARS.test(raw)) return null;

  const [pathPart, query = ''] = splitOnce(raw, '?');
  if (pathPart.includes('#') || query.includes('#')) return null;

  let decoded: string;
  try {
    decoded = decodeURIComponent(pathPart);
  } catch {
    return null;
  }
  // After decoding: still one leading slash, no backslash / control chars, no host-changing forms.
  if (!decoded.startsWith('/') || decoded.startsWith('//') || /[\\\u0000-\u001f\u007f]/.test(decoded)) return null;
  const segments = decoded.split('/').slice(1);
  if (segments.some((s) => s === '.' || s === '..')) return null;
  if (/^[a-z][a-z0-9+.-]*:/i.test(segments[0] ?? '')) return null;

  return query ? `${pathPart}?${query}` : pathPart;
}

/** True when the (normalized) path matches one of the allowlist patterns. Query strings are ignored. */
export function isAllowedPath(path: string, patterns: string[]): boolean {
  const [pathPart] = splitOnce(path, '?');
  const segments = pathPart.split('/').slice(1);
  return patterns.some((pattern) => {
    const want = pattern.split('/').slice(1);
    if (want.length !== segments.length) return false;
    return want.every((w, i) => (w === '*' ? segments[i].length > 0 : w === segments[i]));
  });
}

function splitOnce(value: string, sep: string): [string, string?] {
  const i = value.indexOf(sep);
  return i < 0 ? [value] : [value.slice(0, i), value.slice(i + 1)];
}
