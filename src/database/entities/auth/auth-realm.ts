export const AUTH_REALMS = ['ADMIN', 'MUMIN'] as const;
export type AuthRealm = (typeof AUTH_REALMS)[number];

export function isAuthRealm(value: unknown): value is AuthRealm {
  return typeof value === 'string' && (AUTH_REALMS as readonly string[]).includes(value);
}
