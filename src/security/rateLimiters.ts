import rateLimit from "express-rate-limit";

function parseIntEnv(name: string, fallback: number): number {
  const v = process.env[name];
  if (!v) return fallback;
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export const authLimiter = rateLimit({
  windowMs: parseIntEnv("RATE_LIMIT_AUTH_WINDOW_MS", 15 * 60 * 1000),
  max: parseIntEnv("RATE_LIMIT_AUTH_MAX", 50),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many attempts. Try again later." }
});

export const strictAuthLimiter = rateLimit({
  windowMs: parseIntEnv("RATE_LIMIT_LOGIN_WINDOW_MS", 15 * 60 * 1000),
  max: parseIntEnv("RATE_LIMIT_LOGIN_MAX", 20),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many login attempts. Try again later." }
});

export const mfaLimiter = rateLimit({
  windowMs: parseIntEnv("RATE_LIMIT_MFA_WINDOW_MS", 15 * 60 * 1000),
  max: parseIntEnv("RATE_LIMIT_MFA_MAX", 30),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many MFA attempts. Try again later." }
});

export const uploadLimiter = rateLimit({
  windowMs: parseIntEnv("RATE_LIMIT_UPLOAD_WINDOW_MS", 60 * 60 * 1000),
  max: parseIntEnv("RATE_LIMIT_UPLOAD_MAX", 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Upload rate limit exceeded." }
});

export const apiLimiter = rateLimit({
  windowMs: parseIntEnv("RATE_LIMIT_API_WINDOW_MS", 15 * 60 * 1000),
  max: parseIntEnv("RATE_LIMIT_API_MAX", 300),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests." }
});
