import { Router } from "express";
import { requireAdmin } from "../auth/authMiddleware";
import { getAuditLogLines } from "../logger";
import { authLimiter } from "../security/rateLimiters";

export const adminRouter = Router();

adminRouter.get("/audit-log", authLimiter, requireAdmin, (req, res) => {
  const raw = req.query.limit;
  const limit = typeof raw === "string" && /^\d+$/.test(raw) ? Math.min(parseInt(raw, 10), 500) : 200;
  res.json({ lines: getAuditLogLines(limit) });
});
