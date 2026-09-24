import type { FastifyRequest } from 'fastify';

export interface RequestMeta {
  ip: string;
  userAgent: string | null;
}

/** Client IP (Fastify applies TRUST_PROXY when computing request.ip) and user agent. */
export function requestMeta(req: FastifyRequest): RequestMeta {
  const ua = req.headers['user-agent'];
  return { ip: req.ip, userAgent: typeof ua === 'string' ? ua.slice(0, 512) : null };
}
