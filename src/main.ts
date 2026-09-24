import 'reflect-metadata';
import fastifyCookie from '@fastify/cookie';
import fastifyHelmet from '@fastify/helmet';
import fastifyStatic from '@fastify/static';
import { Logger } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { FastifyAdapter, type NestFastifyApplication } from '@nestjs/platform-fastify';
import { resolve } from 'node:path';
import { AppModule } from './app.module';
import { AppConfig } from './config/config.module';
import { OIDC_PROVIDER, type OidcProvider } from './modules/oidc/oidc.constants';
import { mountOidcProvider } from './modules/oidc/oidc.mount';

async function bootstrap() {
  const adapter = new FastifyAdapter({
    // Applied to request.ip. "true" is never allowed: it would trust a client-supplied X-Forwarded-For.
    trustProxy: Number(process.env.TRUST_PROXY) || false,
    bodyLimit: 64 * 1024,
  });
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, adapter, { bufferLogs: false });
  const config = app.get(AppConfig);
  const fastify = app.getHttpAdapter().getInstance();

  await app.register(fastifyCookie);
  // application/x-www-form-urlencoded (the SSR forms) is parsed by Nest's Fastify adapter itself.
  await app.register(fastifyHelmet, {
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", 'https://fonts.googleapis.com'],
        fontSrc: ["'self'", 'https://fonts.gstatic.com'],
        imgSrc: ["'self'", 'data:'],
        // Login forms post to this origin; oidc-provider then redirects (303) to registered callbacks.
        formAction: ["'self'", 'https:', 'http://localhost:*'],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        objectSrc: ["'none'"],
      },
    },
    hsts: config.isProduction ? { maxAge: 31_536_000, includeSubDomains: true } : false,
    // same-origin (not no-referrer): with no-referrer browsers send "Origin: null" on form POSTs, which the
    // CSRF Origin check must reject. same-origin keeps the real Origin for our own forms and sends
    // nothing to other sites.
    referrerPolicy: { policy: 'same-origin' },
    crossOriginEmbedderPolicy: false,
  });
  await app.register(fastifyStatic, { root: resolve(process.cwd(), 'public'), prefix: '/assets/', maxAge: '1h' });

  await mountOidcProvider(fastify, app.get<OidcProvider>(OIDC_PROVIDER));

  app.enableShutdownHooks();
  await app.listen(config.env.PORT, '0.0.0.0');
  new Logger('bootstrap').log(`oidc_mfa_auth listening on :${config.env.PORT} - issuer ${config.env.ISSUER}`);
}

bootstrap().catch((error: unknown) => {
  // eslint-disable-next-line no-console
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});
