import { Global, Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { AppConfig } from '../config/config.module';
import { buildDataSourceOptions } from './data-source-options';
import { ALL_ENTITIES } from './entities';
import { AuditEventRepository } from './repositories/audit-event.repository';
import { ClientRepository } from './repositories/client.repository';
import { IdentityAccountRepository } from './repositories/identity-account.repository';
import { LoginAttemptRepository } from './repositories/login-attempt.repository';
import { LogoutRepository } from './repositories/logout.repository';
import { HandoffRepository } from './repositories/handoff.repository';
import { MfaFactorRepository, OtpChallengeRepository } from './repositories/mfa.repository';
import { SessionParticipantRepository, SessionRepository } from './repositories/session.repository';
import { SigningKeyRepository } from './repositories/signing-key.repository';
import { SchemaGuardService } from './schema-guard.service';

const REPOSITORIES = [
  IdentityAccountRepository,
  ClientRepository,
  SessionRepository,
  SessionParticipantRepository,
  LoginAttemptRepository,
  AuditEventRepository,
  SigningKeyRepository,
  MfaFactorRepository,
  OtpChallengeRepository,
  LogoutRepository,
  HandoffRepository,
];

/** TypeORM connection + the repository layer. Services depend on these repositories only. */
@Global()
@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [AppConfig],
      useFactory: (config: AppConfig) => buildDataSourceOptions(config.env),
    }),
    TypeOrmModule.forFeature(ALL_ENTITIES),
  ],
  providers: [SchemaGuardService, ...REPOSITORIES],
  exports: REPOSITORIES,
})
export class DatabaseModule {}
