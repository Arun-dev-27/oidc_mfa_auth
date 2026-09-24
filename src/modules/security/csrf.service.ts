import { Injectable } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { AppConfig } from '../../config/config.module';
import { hmacHex, randomToken, safeEqual } from '../../common/crypto.util';

const COOKIE = 'oidc_csrf';

/**
 * CSRF protection for the SSR login / MFA forms:
 *  - a random per-browser secret in an HttpOnly cookie, and
 *  - a form token = HMAC(CSRF_SECRET, interaction uid + cookie secret).
 * A forged cross-site POST has neither the cookie value nor the uid-bound token.
 * The Origin header, when the browser sends one, must also be this issuer.
 */
@Injectable()
export class CsrfService {
  constructor(private readonly config: AppConfig) {}

  /** Returns the token for the page, setting the cookie on first use. */
  issue(req: FastifyRequest, reply: FastifyReply, uid: string): string {
    let secret = req.cookies[COOKIE];
    if (!secret || secret.length < 32) {
      secret = randomToken(32);
      reply.setCookie(COOKIE, secret, {
        httpOnly: true,
        secure: this.config.env.COOKIE_SECURE,
        sameSite: 'lax',
        // '/' so the logout confirmation form (/logout/confirm) is protected by the same secret.
        path: '/',
      });
    }
    return this.token(uid, secret);
  }

  verify(req: FastifyRequest, uid: string, submitted: unknown): boolean {
    const origin = req.headers.origin;
    if (typeof origin === 'string' && origin !== new URL(this.config.env.ISSUER).origin) return false;
    const secret = req.cookies[COOKIE];
    if (!secret || typeof submitted !== 'string' || !submitted) return false;
    return safeEqual(this.token(uid, secret), submitted);
  }

  private token(uid: string, secret: string): string {
    return hmacHex(this.config.env.CSRF_SECRET, `${uid}:${secret}`);
  }
}
