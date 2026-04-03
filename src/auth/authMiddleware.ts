import type { Request, Response, NextFunction } from "express";

export function requireFullAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }
  if (req.session.mustEnrollMfa) {
    return res.status(403).json({ error: "Admin must enroll MFA before using the application.", code: "MFA_ENROLL" });
  }
  if (!req.session.mfaVerified) {
    return res.status(403).json({ error: "MFA verification required.", code: "MFA_VERIFY" });
  }
  next();
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }
  if (req.session.userRole !== "admin") {
    return res.status(403).json({ error: "Admin access only." });
  }
  if (req.session.mustEnrollMfa) {
    return res.status(403).json({ error: "Complete MFA enrollment.", code: "MFA_ENROLL" });
  }
  if (!req.session.mfaVerified) {
    return res.status(403).json({ error: "MFA verification required.", code: "MFA_VERIFY" });
  }
  next();
}

/** Allows MFA enrollment endpoints when admin must enroll */
export function requireAuthenticatedPartial(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }
  next();
}

/** Admin MFA setup (before mfaVerified) or fully authenticated user */
export function requireFullAuthOrMfaEnrollment(req: Request, res: Response, next: NextFunction) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Authentication required." });
  }
  if (req.session.mustEnrollMfa) {
    return next();
  }
  return requireFullAuth(req, res, next);
}

export function sessionUserId(req: Request): string {
  return req.session.userId!;
}
