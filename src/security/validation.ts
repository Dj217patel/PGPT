/**
 * Centralized validation / sanitization for untrusted inputs (UTF-8, reject dangerous patterns).
 */

const NULL_BYTE = /\x00/;
const CRLF = /[\r\n]/;
const TRAVERSAL = /(\.\.[\\/]|\x00|%2e%2e[\\/]|%252e%252e)/i;

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export function assertUtf8String(
  value: unknown,
  field: string,
  maxLen: number,
  options?: { optional?: boolean }
): string | undefined {
  if (value === undefined || value === null) {
    if (options?.optional) return undefined;
    throw new ValidationError(`${field} is required.`);
  }
  if (typeof value !== "string") {
    throw new ValidationError(`${field} must be a string.`);
  }
  const trimmed = value.normalize("NFC").trim();
  if (NULL_BYTE.test(trimmed)) {
    throw new ValidationError(`${field} contains invalid characters.`);
  }
  if (CRLF.test(trimmed)) {
    throw new ValidationError(`${field} contains invalid characters.`);
  }
  if (trimmed.length > maxLen) {
    throw new ValidationError(`${field} is too long (max ${maxLen} characters).`);
  }
  if (!options?.optional && trimmed.length === 0) {
    throw new ValidationError(`${field} cannot be empty.`);
  }
  return trimmed.length ? trimmed : undefined;
}

export function validateEmail(raw: unknown): string {
  const s = assertUtf8String(raw, "Email", 254);
  if (!s) throw new ValidationError("Email is required.");
  const lower = s.toLowerCase();
  if (!/^[\w.!#$%&'*+/=?^`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(lower)) {
    throw new ValidationError("Invalid email format.");
  }
  return lower;
}

export function validateSubjectName(raw: unknown): string {
  const s = assertUtf8String(raw, "Subject name", 200);
  if (!s) throw new ValidationError("Subject name is required.");
  if (!/^[\p{L}\p{N}\s\-_.,()&+'/]+$/u.test(s)) {
    throw new ValidationError("Subject name contains disallowed characters.");
  }
  return s;
}

export function validateSessionId(raw: unknown): string {
  const s = assertUtf8String(raw, "Session", 128, { optional: true });
  if (!s) return "default_session";
  if (!/^[a-zA-Z0-9_\-:.]+$/.test(s)) {
    throw new ValidationError("Invalid session identifier.");
  }
  return s;
}

export function validateChatRole(raw: unknown): "user" | "assistant" {
  if (raw !== "user" && raw !== "assistant") {
    throw new ValidationError("Invalid message role.");
  }
  return raw;
}

export function validateChatMessageBody(raw: unknown): string {
  const s = assertUtf8String(raw, "Message", 50000);
  if (!s) throw new ValidationError("Message is required.");
  return s;
}

export function validateTopicsList(raw: unknown, maxTopics = 50): string[] {
  if (!Array.isArray(raw)) {
    throw new ValidationError("Topics must be an array.");
  }
  if (raw.length === 0) {
    throw new ValidationError("Topics are required.");
  }
  if (raw.length > maxTopics) {
    throw new ValidationError(`At most ${maxTopics} topics allowed.`);
  }
  const out: string[] = [];
  for (const item of raw) {
    const s = assertUtf8String(item, "Topic", 120);
    if (!s) continue;
    if (!/^[\p{L}\p{N}\s\-_]+$/u.test(s)) {
      throw new ValidationError("Invalid topic format.");
    }
    out.push(s);
  }
  if (!out.length) {
    throw new ValidationError("No valid topics provided.");
  }
  return out;
}

export function sanitizeOriginalFilename(original: string): string {
  const base = original.replace(/^[\\/]+/, "").split(/[\\/]/).pop() || "file";
  if (NULL_BYTE.test(base) || TRAVERSAL.test(base)) {
    throw new ValidationError("Invalid file name.");
  }
  const cleaned = base.replace(/[^\w.\- ()[\]]+/g, "_").slice(0, 200);
  if (!cleaned || cleaned === "." || cleaned === "..") {
    throw new ValidationError("Invalid file name.");
  }
  const lower = cleaned.toLowerCase();
  if (!lower.endsWith(".pdf")) {
    throw new ValidationError("Only PDF uploads are allowed.");
  }
  return cleaned;
}

export function validatePdfMagic(buffer: Buffer): void {
  if (buffer.length < 5) {
    throw new ValidationError("File is too small to be a PDF.");
  }
  const header = buffer.subarray(0, 5).toString("ascii");
  if (header !== "%PDF-") {
    throw new ValidationError("Uploaded file is not a valid PDF.");
  }
}

/** Relative path only; blocks scheme and // */
export function validateSafeRedirectTarget(raw: unknown, fallback = "/"): string {
  if (raw === undefined || raw === null) return fallback;
  if (typeof raw !== "string") return fallback;
  const t = raw.normalize("NFC").trim();
  if (!t.startsWith("/") || t.startsWith("//") || t.includes("\\")) {
    return fallback;
  }
  if (TRAVERSAL.test(t) || NULL_BYTE.test(t) || CRLF.test(t)) {
    return fallback;
  }
  return t.slice(0, 512);
}

export function validateHeaderAscii(raw: string | undefined, max = 200): string | undefined {
  if (raw === undefined) return undefined;
  if (typeof raw !== "string") return undefined;
  if (raw.length > max) return undefined;
  if (!/^[\t\x20-\x7e]*$/.test(raw)) {
    return undefined;
  }
  return raw;
}
