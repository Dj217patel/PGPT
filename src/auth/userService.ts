import { pool } from "../db";
import { hashPassword, verifyPassword } from "../security/passwordHash";

export type UserRow = {
  id: string;
  email: string;
  password_hash: string;
  role: "user" | "admin";
  totp_secret: string | null;
  mfa_enabled: boolean;
};

export async function findUserByEmail(email: string): Promise<UserRow | null> {
  const r = await pool.query<UserRow>(
    `
    SELECT id, email, password_hash, role, totp_secret, mfa_enabled
    FROM users
    WHERE email = $1
    `,
    [email.toLowerCase()]
  );
  return r.rows[0] ?? null;
}

export async function findUserById(id: string): Promise<UserRow | null> {
  const r = await pool.query<UserRow>(
    `
    SELECT id, email, password_hash, role, totp_secret, mfa_enabled
    FROM users
    WHERE id = $1
    `,
    [id]
  );
  return r.rows[0] ?? null;
}

export async function createUser(params: {
  email: string;
  password: string;
  role: "user" | "admin";
}): Promise<UserRow> {
  const hash = hashPassword(params.password);
  const r = await pool.query<UserRow>(
    `
    INSERT INTO users (email, password_hash, role)
    VALUES ($1, $2, $3)
    RETURNING id, email, password_hash, role, totp_secret, mfa_enabled
    `,
    [params.email.toLowerCase(), hash, params.role]
  );
  return r.rows[0];
}

export async function updatePassword(userId: string, newPlainPassword: string): Promise<void> {
  const hash = hashPassword(newPlainPassword);
  await pool.query(`UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`, [
    userId,
    hash
  ]);
}

export async function setTotpSecret(userId: string, encryptedSecret: string | null): Promise<void> {
  await pool.query(`UPDATE users SET totp_secret = $2, updated_at = NOW() WHERE id = $1`, [
    userId,
    encryptedSecret
  ]);
}

export async function setMfaEnabled(userId: string, enabled: boolean): Promise<void> {
  await pool.query(`UPDATE users SET mfa_enabled = $2, updated_at = NOW() WHERE id = $1`, [
    userId,
    enabled
  ]);
}

export async function countAdmins(): Promise<number> {
  const r = await pool.query<{ c: string }>(
    `SELECT COUNT(*)::text AS c FROM users WHERE role = 'admin'`
  );
  return Number(r.rows[0]?.c || 0);
}

export function checkPassword(plain: string, hash: string): boolean {
  return verifyPassword(plain, hash);
}
