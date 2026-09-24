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
