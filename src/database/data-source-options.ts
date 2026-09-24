import type { DataSourceOptions } from 'typeorm';
import type { Env } from '../config/env';
import { ALL_ENTITIES } from './entities';
import { OidcMfaAuthSchema1790300000000 } from './migrations/1790300000000-OidcMfaAuthSchema';
import { LogoutDelivery1790400000000 } from './migrations/1790400000000-LogoutDelivery';
import { TrustedHandoff1790500000000 } from './migrations/1790500000000-TrustedHandoff';

/**
 * The existing identity database.
 *
 * search_path is pinned to DB_SCHEMA only, so every unqualified table name (users, auth_*, ...) resolves
 * inside that schema and can never silently hit a same-named table in `public`.
 * synchronize is off for good: schema changes happen only through the explicit migration.
 */
export function buildDataSourceOptions(env: Env): DataSourceOptions {
  return {
    type: 'postgres',
    host: env.DB_HOST,
    port: env.DB_PORT,
    username: env.DB_USER,
    password: env.DB_PASSWORD,
    database: env.DB_NAME,
    schema: env.DB_SCHEMA,
    ssl: env.DB_SSL ? { rejectUnauthorized: true } : false,
    synchronize: false,
    migrationsRun: false,
    dropSchema: false,
    logging: ['error'],
    entities: ALL_ENTITIES,
    migrations: [OidcMfaAuthSchema1790300000000, LogoutDelivery1790400000000, TrustedHandoff1790500000000],
    // Own history table, so this service never collides with another service's migrations.
    migrationsTableName: 'oidc_mfa_auth_migrations',
    extra: {
      max: env.DB_POOL_MAX,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
      // DB_SCHEMA is validated as a plain identifier by the env schema, so inlining it is safe.
      options: `-c search_path=${env.DB_SCHEMA}`,
    },
  };
}
