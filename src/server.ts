import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import multer from "multer";
import fs from "fs";
import path from "path";
import helmet from "helmet";
const pdf = require("pdf-parse");

import { summarizeText } from "./summarizer";
import { uploadSummaryToKnowledgeBase } from "./botpress";
import { getFolders, upsertFolder } from "./folderStore";
import {
  saveConversationSummary,
  saveNote,
  getRecentMessages,
  saveMessage
} from "./chatStore";
import { createSessionMiddleware } from "./auth/sessionMiddleware";
import { requireFullAuth, sessionUserId } from "./auth/authMiddleware";
import { authRouter } from "./auth/authRoutes";
import { adminRouter } from "./admin/adminRoutes";
import { csrfProtectionMiddleware, createCsrfToken, ensureCsrfSecret } from "./security/csrf";
import { apiLimiter, uploadLimiter } from "./security/rateLimiters";
import {
  validateSubjectName,
  validateSessionId,
  validateChatRole,
  validateChatMessageBody,
  validateTopicsList,
  sanitizeOriginalFilename,
  validatePdfMagic,
  ValidationError
} from "./security/validation";
import { mirrorPdfUploadToFirebase } from "./firebase/storageMirror";
import { runMigrations } from "./migrate";
import { ensureBootstrapAdmin } from "./auth/bootstrapAdmin";
import { logError } from "./logger";

type UserPdfState = {
  latestPdfSummary: string;
  latestPdfTitle: string;
  latestPreviousPaperText: string;
};

const userPdfContext = new Map<string, UserPdfState>();

function ctxFor(userId: string): UserPdfState {
  let c = userPdfContext.get(userId);
  if (!c) {
    c = { latestPdfSummary: "", latestPdfTitle: "", latestPreviousPaperText: "" };
    userPdfContext.set(userId, c);
  }
  return c;
}

const app = express();
const port = Number(process.env.PORT || 3000);
const publicRoot = path.resolve(__dirname, "../public");
const indexPath = path.join(publicRoot, "index.html");
const FIREBASE_ENABLED = process.env.FIREBASE_ENABLED === "true";

console.log("Server boot started");
console.log(`Firebase enabled: ${FIREBASE_ENABLED}`);

app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const raw = process.env.CORS_ORIGIN;
      if (!raw) return callback(null, true);
      const allowed = raw.split(",").map((s) => s.trim()).filter(Boolean);
      return allowed.includes(origin) ? callback(null, true) : callback(null, false);
    },
    credentials: true
  })
);
app.use(createSessionMiddleware());
app.use(express.json({ limit: "2mb" }));

app.get("/api/csrf-token", (req: Request, res: Response) => {
  ensureCsrfSecret(req);
  console.log("[CSRF] generated token for GET /api/csrf-token");
  res.json({ csrfToken: createCsrfToken(req) });
});

app.use(express.static(path.resolve(__dirname, "../public"), { index: false }));
console.log("Static/public routes mounted");

app.get("/login", (_req, res) => {
  res.sendFile("login.html", { root: publicRoot });
});

app.use("/auth", authRouter);
console.log("Auth routes mounted");
app.use("/admin", adminRouter);

app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.path !== "/index.html") {
    return next();
  }
  requireFullAuth(req, res, () => {
    res.sendFile(indexPath);
  });
});

app.get("/", requireFullAuth, (_req, res) => {
  res.sendFile("index.html", {
    root: path.resolve(__dirname, "../public")
  });
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024
  },
  fileFilter: (_req, file, cb) => {
    if (file.mimetype !== "application/pdf") {
      return cb(new Error("Only PDF files are allowed."));
    }
    cb(null, true);
  }
});

const protectedApi = express.Router();
protectedApi.use(csrfProtectionMiddleware);
protectedApi.use(apiLimiter);

protectedApi.post(
  "/upload-pdf",
  uploadLimiter,
  (req: Request, res: Response, next: NextFunction) => requireFullAuth(req, res, next),
  upload.single("pdf"),
  async (req: Request, res: Response) => {
    let stage = "upload-pdf";
    try {
      const subjectName = (req.body as { subjectName?: string }).subjectName;
      const file = req.file;
      console.log("[UPLOAD-PDF] start", {
        subjectName,
        hasFile: !!file,
        originalname: file?.originalname,
        mimetype: file?.mimetype,
        size: file?.size,
        hasBuffer: !!file?.buffer,
        bufferBytes: file?.buffer?.byteLength
      });

      if (!file?.buffer) {
        return res.status(400).json({
          error: "No PDF uploaded. Expected multipart field name: 'pdf'."
        });
      }

      console.log("[UPLOAD-PDF] validating PDF magic bytes...");
      stage = "validate_pdf_magic";
      validatePdfMagic(file.buffer);

      const subjectRaw = (req.body as { subjectName?: string }).subjectName;
      if (subjectRaw !== undefined && String(subjectRaw).trim()) {
        validateSubjectName(subjectRaw);
      }
      const safeName = sanitizeOriginalFilename(file.originalname);
      const uid = sessionUserId(req);

      console.log("[UPLOAD-PDF] parsing PDF with pdf-parse...");
      stage = "parse_pdf";
      const parsed = await pdf(file.buffer);
      const extractedText = parsed.text?.trim() || "";
      console.log("[UPLOAD-PDF] extractedTextLength=", extractedText.length);

      if (!extractedText) {
        return res.status(400).json({ error: "Could not extract readable text from the PDF." });
      }

      console.log("[UPLOAD-PDF] summarizing extracted text...");
      stage = "summarize_text";
      if (FIREBASE_ENABLED) {
        void mirrorPdfUploadToFirebase({
          userId: uid,
          safeFilename: safeName,
          buffer: file.buffer
        });
      }

      const summaryText = await summarizeText(extractedText);

      console.log("[UPLOAD-PDF] uploading summary to knowledge base...");
      stage = "upload_kb";
      const kbFile = await uploadSummaryToKnowledgeBase({
        summaryText,
        originalFileName: safeName
      });

      const c = ctxFor(uid);
      c.latestPdfSummary = summaryText;
      c.latestPdfTitle = kbFile.title;
      return res.json({
        message: "PDF processed and uploaded to Botpress Knowledge Base.",
        title: kbFile.title,
        preview: summaryText.slice(0, 1500)
      });
    } catch (e) {
      if (e instanceof ValidationError) {
        return res.status(400).json({ error: e.message });
      }
      console.error("[UPLOAD-PDF] caught error (stage=" + stage + "):", e);
      logError("upload-pdf failed", {
        stage,
        err: e instanceof Error ? e.message : String(e)
      });
      if (stage === "parse_pdf") {
        return res.status(400).json({ error: "PDF parsing failed." });
      }
      if (stage === "summarize_text") {
        return res.status(500).json({ error: "PDF summarization failed." });
      }
      if (stage === "upload_kb") {
        return res.status(500).json({ error: "Knowledge base upload failed." });
      }
      return res.status(500).json({ error: "Could not process PDF." });
    }
  }
);

/** requireFullAuth + async JSON handlers */
function withAuth(
  handler: (req: Request, res: Response) => Promise<void | Response>
): (req: Request, res: Response, next: NextFunction) => void {
  return (req, res, next) => {
    requireFullAuth(req, res, () => {
      void handler(req, res).catch((e) => {
        if (e instanceof ValidationError) {
          return res.status(400).json({ error: e.message });
        }
        logError("API error", { err: e instanceof Error ? e.message : String(e) });
        res.status(500).json({ error: "Request failed." });
      });
    });
  };
}

protectedApi.post(
  "/chat/save-message",
  withAuth(async (req, res) => {
    const { sessionId, role, message } = req.body as {
      sessionId?: string;
      role?: "user" | "assistant";
      message?: string;
    };
    const userId = sessionUserId(req);
    const sid = validateSessionId(sessionId);
    const r = validateChatRole(role);
    const msg = validateChatMessageBody(message);
    await saveMessage({ userId, sessionId: sid, role: r, message: msg });
    res.json({ success: true });
  })
);

protectedApi.get(
  "/folders",
  withAuth(async (req, res) => {
    const folders = await getFolders(sessionUserId(req));
    res.json({ folders });
  })
);

protectedApi.post(
  "/folders/upsert",
  withAuth(async (req, res) => {
    const { subjectName } = req.body as { subjectName?: string };
    const name = validateSubjectName(subjectName);
    const folder = await upsertFolder(sessionUserId(req), name);
    res.json({ folder });
  })
);

protectedApi.post(
  "/notes/generate",
  withAuth(async (req, res) => {
    const { subjectName, sessionId } = req.body as { subjectName?: string; sessionId?: string };
    const name = validateSubjectName(subjectName);
    const sid = validateSessionId(sessionId);
    const uid = sessionUserId(req);
    const folder = await upsertFolder(uid, name);
    const recentMessages = sid
      ? await getRecentMessages({ userId: uid, sessionId: sid, limit: 20 })
      : [];

    const c = ctxFor(uid);

    const chatText = recentMessages.length
      ? recentMessages
          .map((m: { role: string; message: string }) => `${m.role.toUpperCase()}: ${m.message}`)
          .join("\n")
      : "No recent chat messages found.";

    const introduction = `These notes are generated for the subject "${name}" using the uploaded document and the saved conversation with Judo. They are written in a study-friendly format for revision and exam preparation.`;

    const coreConcepts = c.latestPdfSummary
      ? c.latestPdfSummary
      : "No uploaded document summary is currently available.";

    const detailedExplanation = `
The uploaded document provides the main source material for this subject. The discussion with Judo helps clarify ideas, explain difficult parts, and highlight what matters most.

The following chat-based context was found:
${chatText}
    `.trim();

    const importantPoints = [
      "Focus on the main definitions and technical terms.",
      "Revise repeated concepts that came up in both the document and the chat.",
      "Pay attention to explanations that help in theory answers.",
      "Use these notes as a base for long-answer and short-answer preparation."
    ];

    const examplesSection = `
Examples and applications should be built from the main concepts in the uploaded document.
Where possible, connect theoretical ideas to practical use-cases, diagrams, workflows, or system-level explanations.
    `.trim();

    const examRevision = `
Exam-Oriented Revision:
1. Learn the core definitions clearly.
2. Prepare 4–6 key points for each major concept.
3. Revise differences, classifications, advantages, and limitations.
4. Practice writing short and long descriptive answers from these notes.
    `.trim();

    const conclusion = `These notes combine document understanding and chat-based clarification into one structured study resource for ${name}.`;

    const detailedNotes = `
Subject: ${name}

Title: ${c.latestPdfTitle || `${name} Study Notes`}

1. Introduction
${introduction}

2. Core Concepts from Document
${coreConcepts}

3. Detailed Explanation
${detailedExplanation}

4. Important Points
${importantPoints.map((point, index) => `${index + 1}. ${point}`).join("\n")}

5. Examples / Applications
${examplesSection}

6. Exam-Focused Revision
${examRevision}

7. Conclusion
${conclusion}
    `.trim();

    const summary = await summarizeText(detailedNotes);

    await saveConversationSummary({
      userId: uid,
      sessionId: sid || "default_session",
      summary
    });

    await saveNote({
      folderId: folder.id,
      userId: uid,
      sessionId: sid || "default_session",
      title: `${name} Notes`,
      content: detailedNotes,
      category: "study-notes"
    });

    res.json({
      success: true,
      folder,
      notes: detailedNotes
    });
  })
);

protectedApi.post(
  "/previous-paper/analyze",
  uploadLimiter,
  (req: Request, res: Response, next: NextFunction) => requireFullAuth(req, res, next),
  upload.single("pdf"),
  async (req: Request, res: Response) => {
    try {
      if (!req.file?.buffer) {
        return res.status(400).json({ error: "Please upload a previous paper PDF." });
      }
      validatePdfMagic(req.file.buffer);
      sanitizeOriginalFilename(req.file.originalname);
      const uid = sessionUserId(req);
      const parsed = await pdf(req.file.buffer);
      const extractedText = parsed.text?.trim() || "";
      if (!extractedText) {
        return res.status(400).json({ error: "Could not extract readable text from the previous paper." });
      }
      const c = ctxFor(uid);
      c.latestPreviousPaperText = extractedText;

      const words = extractedText
        .toLowerCase()
        .replace(/[^a-z0-9\s]/g, " ")
        .split(/\s+/)
        .filter(Boolean);

      const stopWords = new Set([
        "the", "is", "are", "was", "were", "and", "or", "of", "to", "in", "on", "for",
        "with", "a", "an", "by", "as", "at", "from", "that", "this", "it", "be", "can",
        "what", "write", "explain", "define", "discuss", "short", "note", "answer"
      ]);

      const freq: Record<string, number> = {};

      for (const word of words) {
        if (word.length < 4 || stopWords.has(word)) continue;
        freq[word] = (freq[word] || 0) + 1;
      }

      const topics = Object.entries(freq)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([word]) => word);

      return res.json({ topics });
    } catch (e) {
      if (e instanceof ValidationError) {
        return res.status(400).json({ error: e.message });
      }
      logError("previous-paper/analyze failed", { err: e instanceof Error ? e.message : String(e) });
      return res.status(500).json({ error: "Analysis failed." });
    }
  }
);

protectedApi.post(
  "/previous-paper/generate-notes",
  withAuth(async (req, res) => {
    const { topics } = req.body as { topics?: string[] };
    const list = validateTopicsList(topics);
    const notes = list
      .map((topic, index) => {
        return `
${index + 1}. Topic: ${topic}

Introduction:
${topic} is an important exam-oriented topic identified from previous papers.

Definition:
Write the formal definition of ${topic} in clear academic language.

Main Explanation:
Explain the concept of ${topic} in detail with all important sub-points.

Important Points:
- Key concept 1 of ${topic}
- Key concept 2 of ${topic}
- Key concept 3 of ${topic}

Examples / Applications:
Provide suitable examples, use-cases, or system relevance for ${topic}.

Exam-Oriented Notes:
Focus on definitions, differences, diagrams, and repeated concepts related to ${topic}.
        `.trim();
      })
      .join("\n\n");

    res.json({ notes });
  })
);

app.use(protectedApi);

app.use((err: unknown, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof Error && err.message === "Only PDF files are allowed.") {
    return res.status(400).json({ error: err.message });
  }
  logError("Request error", { err: err instanceof Error ? err.message : String(err) });
  if (!res.headersSent) {
    res.status(500).json({ error: "Request failed." });
  }
});

app.use((_req: Request, res: Response) => {
  res.status(404).json({ error: "Not found." });
});

async function startServer() {
  const isProd = process.env.NODE_ENV === "production";

  try {
    console.log("Running DB migrations...");
    await runMigrations();
    console.log("Migrations complete");
  } catch (err) {
    console.error("Migration failed:", err);
    if (isProd) process.exit(1);
  }

  try {
    await ensureBootstrapAdmin();
  } catch (err) {
    console.error("Bootstrap admin failed:", err);
    if (isProd) process.exit(1);
  }

  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
  });
}

startServer();
