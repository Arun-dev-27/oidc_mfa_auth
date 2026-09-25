import { Body, Controller, Get, Param, Post, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { InteractionService, type LoginForm, type MfaForm } from './interaction.service';
import { SIGNIN_PREFIX } from './signin-paths';

const UID = /^[A-Za-z0-9_-]{8,64}$/;

/**
 * SSR sign-in endpoints for the oidc-provider interaction (spec §30):
 *   GET  /signin/:uid                  login page, or silent SSO / MFA decision
 *   POST /signin/:uid/password         ITS ID + password
 *   POST /signin/:uid/verify           verify the code
 *   POST /signin/:uid/verify/resend    send a new OTP
 *   POST /signin/:uid/verify/switch    use another method (Email / SMS / authenticator)
 *   POST /signin/:uid/cancel           cancel -> access_denied back to the application
 */
@Controller(SIGNIN_PREFIX)
export class InteractionController {
  constructor(private readonly interactions: InteractionService) {}

  @Get(':uid')
  show(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.show(req, reply, uid);
  }

  @Post(':uid/password')
  login(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: LoginForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.login(req, reply, uid, body ?? {});
  }

  @Post(':uid/verify')
  mfa(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.verifyMfa(req, reply, uid, body ?? {});
  }

  @Post(':uid/verify/resend')
  resend(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.sendCode(req, reply, uid, body ?? {}, true);
  }

  @Post(':uid/verify/switch')
  switchMethod(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: MfaForm) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.sendCode(req, reply, uid, body ?? {}, false);
  }

  @Post(':uid/cancel')
  abort(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('uid') uid: string, @Body() body: { csrf?: string }) {
    if (!UID.test(uid)) return reply.code(404).send();
    return this.interactions.abort(req, reply, uid, body ?? {});
  }
}
