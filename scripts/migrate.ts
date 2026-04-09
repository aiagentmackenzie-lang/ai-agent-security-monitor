import 'dotenv/config';
import { initDb } from '../src/db/init.js';

async function migrate() {
  console.log('Running database migrations...');
  await initDb(process.env.DATABASE_URL!);
  console.log('Migrations complete');
}

migrate().catch((e) => {
  console.error('Migration failed:', e);
  process.exit(1);
});
