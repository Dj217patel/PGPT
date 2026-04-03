import { pool } from "./db";

export async function saveMessage(params: {
  userId: string;
  sessionId: string;
  role: "user" | "assistant";
  message: string;
}) {
  const { userId, sessionId, role, message } = params;

  await pool.query(
    `
    INSERT INTO messages (user_id, session_id, role, message)
    VALUES ($1, $2, $3, $4)
    `,
    [userId, sessionId, role, message]
  );
}

export async function getRecentMessages(params: {
  userId: string;
  sessionId: string;
  limit?: number;
}) {
  const { userId, sessionId, limit = 10 } = params;

  const result = await pool.query(
    `
    SELECT id, role, message, created_at
    FROM messages
    WHERE user_id = $1 AND session_id = $2
    ORDER BY id DESC
    LIMIT $3
    `,
    [userId, sessionId, limit]
  );

  return result.rows.reverse();
}

export async function saveConversationSummary(params: {
  userId: string;
  sessionId: string;
  summary: string;
  messageRangeStart?: number | null;
  messageRangeEnd?: number | null;
}) {
  const {
    userId,
    sessionId,
    summary,
    messageRangeStart = null,
    messageRangeEnd = null
  } = params;

  await pool.query(
    `
    INSERT INTO conversation_summaries (
      user_id, session_id, summary, message_range_start, message_range_end
    )
    VALUES ($1, $2, $3, $4, $5)
    `,
    [userId, sessionId, summary, messageRangeStart, messageRangeEnd]
  );
}

export async function saveNote(params: {
  folderId: number;
  userId: string;
  sessionId?: string | null;
  title: string;
  content: string;
  category?: string | null;
}) {
  const {
    folderId,
    userId,
    sessionId = null,
    title,
    content,
    category = null
  } = params;

  await pool.query(
    `
    INSERT INTO notes (folder_id, user_id, session_id, title, content, category)
    VALUES ($1, $2, $3, $4, $5, $6)
    `,
    [folderId, userId, sessionId, title, content, category]
  );
}