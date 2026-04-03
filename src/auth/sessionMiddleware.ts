import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { pool } from "../db";

export function createSessionMiddleware() {
  const PgSession = connectPgSimple(session);
  const secret = process.env.SESSION_SECRET;
  const isProd = process.env.NODE_ENV === "production";

  if (!secret) {
    throw new Error("SESSION_SECRET environment variable is required.");
  }
  if (isProd && secret.length < 32) {
    throw new Error("SESSION_SECRET must be at least 32 characters in production.");
  }

  const ms = Number(process.env.SESSION_MAX_AGE_MS || 7 * 24 * 60 * 60 * 1000);

  return session({
    store: new PgSession({
      pool,
      tableName: "user_sessions",
      createTableIfMissing: false
    }),
    name: "pgpt.sid",
    secret,
    resave: false,
    saveUninitialized: true,
    rolling: true,
    cookie: {
      httpOnly: true,
      secure: isProd,
      sameSite: "lax",
      maxAge: ms
    }
  });
}
