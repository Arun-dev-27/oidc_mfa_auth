import type { FormActions } from './auth-pages.service';

/**
 * Public URLs of the Core sign-in pages (the oidc-provider "interaction"):
 *   GET  /signin/:uid                  login page, or silent SSO / MFA decision
 *   POST /signin/:uid/password         ITS ID + password
 *   POST /signin/:uid/verify           verify the code
 *   POST /signin/:uid/verify/resend    send a new OTP
 *   POST /signin/:uid/verify/switch    use another method (Email / SMS / authenticator)
 *   POST /signin/:uid/cancel           cancel -> access_denied back to the application
 * oidc-provider scopes its _interaction cookies to this path automatically.
 */
export const SIGNIN_PREFIX = 'signin';

export const signinUrl = (uid: string) => `/${SIGNIN_PREFIX}/${uid}`;

export function signinActions(uid: string): FormActions {
  const base = signinUrl(uid);
  return { login: `${base}/password`, verify: `${base}/verify`, resend: `${base}/verify/resend`, switch: `${base}/verify/switch`, cancel: `${base}/cancel` };
}
