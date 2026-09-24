import { Global, Injectable, Module } from '@nestjs/common';
import { type Env, loadDotEnv, parseEnv } from './env';

/** Typed, validated configuration. Inject AppConfig and read `config.env.X`. */
@Injectable()
export class AppConfig {
  readonly env: Env;

  constructor() {
    loadDotEnv();
    this.env = parseEnv();
  }

  get isProduction(): boolean {
    return this.env.NODE_ENV === 'production';
  }
}

@Global()
@Module({
  providers: [AppConfig],
  exports: [AppConfig],
})
export class ConfigModule {}
