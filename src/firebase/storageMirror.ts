import * as admin from "firebase-admin";
import { logWarn } from "../logger";

let initialized = false;

function tryInit(): boolean {
  if (initialized) return true;
  const json = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  const bucket = process.env.FIREBASE_STORAGE_BUCKET;
  if (!json || !bucket) {
    return false;
  }
  try {
    const cred = JSON.parse(json) as admin.ServiceAccount;
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(cred),
        storageBucket: bucket
      });
    }
    initialized = true;
    return true;
  } catch (e) {
    logWarn("Firebase admin init failed", { err: String(e) });
    return false;
  }
}

/**
 * Best-effort mirror of raw PDF bytes to Firebase Storage (user-scoped path).
 * Does not throw; failures are logged only so local/RAG flow continues.
 */
export async function mirrorPdfUploadToFirebase(params: {
  userId: string;
  safeFilename: string;
  buffer: Buffer;
}): Promise<string | null> {
  if (!tryInit()) {
    return null;
  }
  try {
    const bucket = admin.storage().bucket();
    const stamp = Date.now();
    const path = `uploads/${params.userId}/${stamp}-${params.safeFilename.replace(/[^\w.\-]+/g, "_")}`;
    const file = bucket.file(path);
    await file.save(params.buffer, {
      contentType: "application/pdf",
      metadata: {
        metadata: { userId: params.userId }
      }
    });
    return path;
  } catch (e) {
    logWarn("Firebase Storage mirror failed", { err: String(e) });
    return null;
  }
}
