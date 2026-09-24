import { isAllowedPath, normalizeRelativePath } from '../src/modules/handoff/handoff-path';

const PATTERNS = ['/dashboard', '/events/*', '/events/*/details', '/bookings/*'];

describe('handoff requested_path', () => {
  it.each(['/dashboard', '/events/123', '/events/123/details?tab=seats', '/bookings/B-7'])('accepts %s', (p) => {
    expect(normalizeRelativePath(p)).toBe(p);
    expect(isAllowedPath(p, PATTERNS)).toBe(true);
  });

  it.each([
    'https://evil.example/x',
    '//evil.example',
    '/\\evil.example',
    'events/1',
    ' /dashboard',
    '/dashboard ',
    '/../admin',
    '/events/1/../../admin',
    '/%2e%2e/admin',
    '/%2F%2Fevil.example',
    '/%0d%0aSet-Cookie:x',
    '/javascript:alert(1)',
    '/events/1#frag',
    '/bad%zz',
    '',
    '/' + 'a'.repeat(600),
  ])('rejects %j', (p) => {
    expect(normalizeRelativePath(p)).toBeNull();
  });

  it('rejects non-strings', () => {
    expect(normalizeRelativePath(undefined)).toBeNull();
    expect(normalizeRelativePath(['/dashboard'])).toBeNull();
  });

  it('"*" matches exactly one non-empty segment', () => {
    expect(isAllowedPath('/events', PATTERNS)).toBe(false);
    expect(isAllowedPath('/events/', PATTERNS)).toBe(false);
    expect(isAllowedPath('/events/1/2', PATTERNS)).toBe(false);
    expect(isAllowedPath('/events/1/details', PATTERNS)).toBe(true);
    expect(isAllowedPath('/admin/users', PATTERNS)).toBe(false);
  });
});
