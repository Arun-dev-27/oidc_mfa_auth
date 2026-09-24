import type { FastifyInstance } from 'fastify';
import { OIDC_MOUNT_PATHS, type OidcProvider } from './oidc.constants';

/**
 * Serves the protocol endpoints with oidc-provider (a Koa app) inside Fastify.
 *
 * The routes live in their own encapsulated plugin whose content-type parsers are replaced by a
 * no-op: the request body stream stays unread, so oidc-provider parses /token and /auth POST
 * bodies itself (it must see the raw body for client authentication). Fastify then hands the raw
 * Node request/response to the provider and steps aside (reply.hijack).
 */
export async function mountOidcProvider(fastify: FastifyInstance, provider: OidcProvider): Promise<void> {
  const callback = provider.callback();
  await fastify.register(async (scope) => {
    scope.removeAllContentTypeParsers();
    scope.addContentTypeParser('*', (_req, _payload, done) => done(null, undefined));
    for (const path of OIDC_MOUNT_PATHS) {
      scope.route({
        method: ['GET', 'POST', 'OPTIONS'],
        url: path,
        handler: async (req, reply) => {
          reply.hijack();
          // Security headers were already added by helmet's onRequest hook; oidc-provider sets its own.
          for (const [name, value] of Object.entries(reply.getHeaders())) {
            if (value !== undefined && !reply.raw.headersSent) reply.raw.setHeader(name, value as string);
          }
          await callback(req.raw, reply.raw);
        },
      });
    }
  });
}
