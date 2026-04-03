import fs from "fs";
import path from "path";
import { pool } from "./db";
import { logInfo, logError } from "./logger";

export async function runMigrations(): Promise<void> {
  const sqlPath = path.join(__dirname, "..", "migrations", "001_secured_schema.sql");
  const sql = fs.readFileSync(sqlPath, "utf8");
  await pool.query(sql);
  logInfo("Database migrations applied.");
}

export async function runMigrationsIfEnabled(): Promise<void> {
  if (process.env.RUN_MIGRATIONS_ON_START !== "true") {
    return;
  }
  try {
    await runMigrations();
  } catch (e) {
    logError("Migration failed", { err: e instanceof Error ? e.message : String(e) });
    throw e;
  }
}

if (require.main === module) {
  runMigrations()
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
}
