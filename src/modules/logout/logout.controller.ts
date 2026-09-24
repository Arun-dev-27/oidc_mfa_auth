import { Body, Controller, Get, Post, Query, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { LogoutService, type LogoutParams } from './logout.service';

/**
 * Core logout endpoints (spec §25, advertised as end_session_endpoint):
 *   GET  /logout?client_id=...&post_logout_redirect_uri=...&state=...[&id_token_hint=...]
 *   POST /logout/confirm   (confirmation page form)
 */
@Controller('logout')
export class LogoutController {
  constructor(private readonly logout: LogoutService) {}

  @Get()
  start(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Query() query: LogoutParams) {
    return this.logout.start(req, reply, query ?? {});
  }

  @Post('confirm')
  confirm(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Body() body: LogoutParams) {
    return this.logout.confirm(req, reply, body ?? {});
  }
}

const LOGOUT_PARAMS = ['client_id', 'id_token_hint', 'post_logout_redirect_uri', 'state'] as const;

/**
 * oidc-provider's default logout paths (its own end-session feature is disabled): clients or bookmarks
 * using /session/end[/confirm] are sent to Core's /logout with the standard parameters, never a 404.
 */
@Controller('session/end')
export class LegacyEndSessionController {
  @Get()
  get(@Res() reply: FastifyReply, @Query() query: Record<string, unknown>) {
    return redirectToLogout(reply, query);
  }

  @Get('confirm')
  getConfirm(@Res() reply: FastifyReply, @Query() query: Record<string, unknown>) {
    return redirectToLogout(reply, query);
  }

  @Post('confirm')
  postConfirm(@Res() reply: FastifyReply, @Query() query: Record<string, unknown>) {
    return redirectToLogout(reply, query);
  }
}

function redirectToLogout(reply: FastifyReply, query: Record<string, unknown>) {
  const q = new URLSearchParams();
  for (const key of LOGOUT_PARAMS) if (typeof query?.[key] === 'string') q.set(key, query[key] as string);
  return reply.code(303).header('location', `/logout${q.size ? `?${q}` : ''}`).send();
}
