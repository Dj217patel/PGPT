type LogLevel = "info" | "warn" | "error";

const MAX_AUDIT_LINES = 500;
const auditRing: string[] = [];
let redactPatterns: RegExp[] = [
  /password["']?\s*[:=]\s*["'][^"']*["']/gi,
  /otp["']?\s*[:=]\s*["'][^"']*["']/gi,
  /token["']?\s*[:=]\s*["'][^"']*["']/gi,
  /Bearer\s+[\w-_.]+/gi,
  /api[_-]?key["']?\s*[:=]\s*["'][^"']*["']/gi
];

function redact(message: string): string {
  let out = message;
  for (const re of redactPatterns) {
    out = out.replace(re, "[REDACTED]");
  }
  return out;
}

function pushAudit(formatted: string) {
  auditRing.push(`${new Date().toISOString()} ${formatted}`);
  if (auditRing.length > MAX_AUDIT_LINES) {
    auditRing.splice(0, auditRing.length - MAX_AUDIT_LINES);
  }
}

function formatParts(level: LogLevel, msg: string, meta?: Record<string, unknown>) {
  const safe = redact(msg);
  let extra = "";
  if (meta && Object.keys(meta).length) {
    try {
      extra = " " + redact(JSON.stringify(meta));
    } catch {
      extra = " [meta]";
    }
  }
  return `[${level.toUpperCase()}] ${safe}${extra}`;
}

export function logInfo(msg: string, meta?: Record<string, unknown>) {
  const line = formatParts("info", msg, meta);
  pushAudit(line);
  console.log(line);
}

export function logWarn(msg: string, meta?: Record<string, unknown>) {
  const line = formatParts("warn", msg, meta);
  pushAudit(line);
  console.warn(line);
}

export function logError(msg: string, meta?: Record<string, unknown>) {
  const line = formatParts("error", msg, meta);
  pushAudit(line);
  console.error(line);
}

export function getAuditLogLines(limit = 200): string[] {
  const n = Math.min(limit, auditRing.length);
  return auditRing.slice(-n);
}
