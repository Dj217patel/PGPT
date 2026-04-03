import { pool } from "./db";

export async function getFolders(userId: string) {
  const result = await pool.query(
    `
    SELECT id, subject_name, created_at
    FROM folders
    WHERE user_id = $1
    ORDER BY subject_name ASC
    `,
    [userId]
  );

  return result.rows;
}

export async function upsertFolder(userId: string, subjectName: string) {
  const existing = await pool.query(
    `
    SELECT id, subject_name
    FROM folders
    WHERE user_id = $1 AND subject_name = $2
    `,
    [userId, subjectName]
  );

  if (existing.rows.length > 0) {
    return existing.rows[0];
  }

  const created = await pool.query(
    `
    INSERT INTO folders (user_id, subject_name)
    VALUES ($1, $2)
    RETURNING id, subject_name
    `,
    [userId, subjectName]
  );

  return created.rows[0];
}