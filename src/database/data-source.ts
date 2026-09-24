import 'reflect-metadata';
import { DataSource } from 'typeorm';
import { loadDotEnv, parseEnv } from '../config/env';
import { buildDataSourceOptions } from './data-source-options';

/** Used by the TypeORM CLI (npm run migration:run / migration:show / migration:revert) and the scripts. */
loadDotEnv();
const AppDataSource = new DataSource(buildDataSourceOptions(parseEnv()));
export default AppDataSource;
