import type { Request, Response, NextFunction } from "express";
import CsrfTokens from "csrf";

const tokens = new CsrfTokens();

export function ensureCsrfSecret(req: Request): void {
  if (!req.session.csrfSecret) {
    req.session.csrfSecret = tokens.secretSync();
  }
}

export function createCsrfToken(req: Request): string {
  ensureCsrfSecret(req);
  return tokens.create(req.session.csrfSecret!);
}

export function verifyCsrfToken(req: Request, token: string | undefined): boolean {
  if (!token || !req.session.csrfSecret) {
    return false;
  }
  return tokens.verify(req.session.csrfSecret, token);
}

export function csrfProtectionMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.method === "GET" || req.method === "HEAD" || req.method === "OPTIONS") {
    return next();
  }
  const headerRaw = req.headers["x-csrf-token"];
  const token = Array.isArray(headerRaw) ? headerRaw[0] : headerRaw;
  if (!verifyCsrfToken(req, token)) {
    return res.status(403).json({ error: "Invalid or missing CSRF token." });
  }
  next();
}
