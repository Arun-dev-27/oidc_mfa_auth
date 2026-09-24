import { Body, Controller, Get, Param, Post, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { InteractionService, type LoginForm, type MfaForm } from './interaction.service';

const UID = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * SSR endpoints for the oidc-provider interaction (spec §30):
 *   GET  /interaction/:uid              login page, or silent SSO / MFA decision
 *   POST /interaction/:uid/login        ITS ID + password
 *   POST /interaction/:uid/mfa          verify the code
 *   POST /interaction/:uid/mfa/resend   send a new OTP
 *   POST /interaction/:uid/mfa/switch   use another method (Email / SMS / authenticator)
 *   POST /interaction/:uid/abort        cancel -> access_denied back to the application
 */
@Controller('interaction')
export class InteractionController {
  constructor(private readonly interactions: InteractionService) {}

  @Get(':uid')
  show(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.show(req, reply, uid);
  }

  @Post(':uid/login')
  login(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: LoginForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.login(req, reply, uid, body ?? {});
  }

  @Post(':uid/mfa')
  mfa(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.verifyMfa(req, reply, uid, body ?? {});
  }

  @Post(':uid/mfa/resend')
  resend(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.sendCode(req, reply, uid, body ?? {}, true);
  }

  @Post(':uid/mfa/switch')
  switchMethod(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.sendCode(req, reply, uid, body ?? {}, false);
  }

  @Post(':uid/abort')
  abort(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: { csrf?: string }) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.abort(req, reply, uid, body ?? {});
  }
}
