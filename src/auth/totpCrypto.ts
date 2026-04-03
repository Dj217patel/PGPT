import crypto from "crypto";

function key32(): Buffer {
  const raw = process.env.MFA_ENCRYPTION_KEY || process.env.SESSION_SECRET || "";
  if (!raw) {
    throw new Error("Set SESSION_SECRET or MFA_ENCRYPTION_KEY before using MFA.");
  }
  return crypto.createHash("sha256").update(raw, "utf8").digest();
}

export function encryptSecret(plain: string): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key32(), iv);
  const enc = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64url");
}

export function decryptSecret(blob: string): string {
  const buf = Buffer.from(blob, "base64url");
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const data = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key32(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]).toString("utf8");
}
