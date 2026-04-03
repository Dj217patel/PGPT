import { generateSecret, generateURI, verifySync } from "otplib";
import { decryptSecret, encryptSecret } from "./totpCrypto";

export function generateTotpSecret(): string {
  return generateSecret();
}

export function otpAuthUrl(email: string, secret: string): string {
  const issuer = process.env.APP_NAME || "PGPT Secured";
  return generateURI({
    issuer,
    label: email,
    secret
  });
}

export function verifyTotpToken(secretPlain: string, token: string): boolean {
  const cleaned = token.replace(/\s/g, "");
  if (!/^\d{6,8}$/.test(cleaned)) {
    return false;
  }
  try {
    const result = verifySync({ secret: secretPlain, token: cleaned });
    return result.valid === true;
  } catch {
    return false;
  }
}

export function encryptTotpForStorage(secretPlain: string): string {
  return encryptSecret(secretPlain);
}

export function decryptTotpFromStorage(blob: string): string {
  return decryptSecret(blob);
}
