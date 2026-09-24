import { Body, Controller, Get, Param, Post, Req, Res } from '@nestjs/common';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { HandoffService } from './handoff.service';

type Form = Record<string, string | undefined>;

/**
 * Trusted handoff endpoints (Handoff spec §6, §8; Core spec §30):
 *   POST /v1/handoff/requests          source BU backend, client-authenticated, JSON or form body
 *   GET  /v1/handoff/:id               browser: Core session check -> signed assertion auto-POST
 *   POST /v1/handoff/:id/login         Core login when the realm session is missing
 *   POST /v1/handoff/:id/mfa[/resend|/switch]   target assurance requirement
 *   POST /v1/handoff/:id/abort         cancel
 */
@Controller('v1/handoff')
export class HandoffController {
  constructor(private readonly handoff: HandoffService) {}

  @Post('requests')
  async create(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Body() body: Record<string, unknown>) {
    const result = await this.handoff.createRequest(req, body ?? {});
    return reply.code(result.status).header('cache-control', 'no-store').send(result.body);
  }

  @Get(':id')
  open(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string) {
    return this.handoff.open(req, reply, id);
  }

  @Post(':id/login')
  login(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string, @Body() body: Form) {
    return this.handoff.login(req, reply, id, body ?? {});
  }

  @Post(':id/mfa')
  mfa(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string, @Body() body: Form) {
    return this.handoff.verifyMfa(req, reply, id, body ?? {});
  }

  @Post(':id/mfa/resend')
  resend(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string, @Body() body: Form) {
    return this.handoff.sendCode(req, reply, id, body ?? {}, true);
  }

  @Post(':id/mfa/switch')
  switchMethod(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string, @Body() body: Form) {
    return this.handoff.sendCode(req, reply, id, body ?? {}, false);
  }

  @Post(':id/abort')
  abort(@Req() req: FastifyRequest, @Res() reply: FastifyReply, @Param('id') id: string, @Body() body: Form) {
    return this.handoff.abort(req, reply, id, body ?? {});
  }
}
