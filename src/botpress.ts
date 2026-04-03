const BOTPRESS_API_BASE = "https://api.botpress.cloud/v1";

function requireEnv(name: string): string {
  const value = process.env[name];

  if (!value) {
    throw new Error(`Missing environment variable: ${name}`);
  }

  return value;
}

export async function uploadSummaryToKnowledgeBase(params: {
  summaryText: string;
  originalFileName: string;
}): Promise<{ fileId: string; key: string; title: string }> {
  const botId = requireEnv("BOTPRESS_BOT_ID");
  const token = requireEnv("BOTPRESS_API_KEY");
  const kbId = requireEnv("BOTPRESS_KB_ID");

  const timestamp = Date.now();

  const safeBaseName =
    params.originalFileName
      .replace(/\.pdf$/i, "")
      .replace(/[^a-zA-Z0-9-_ ]/g, "")
      .trim()
      .replace(/\s+/g, "-")
      .toLowerCase() || "document";

  const key = `kb-summaries/${safeBaseName}-${timestamp}.txt`;
  const title = `${safeBaseName}-summary`;
  const buffer = Buffer.from(params.summaryText, "utf8");

  const createRes = await fetch(`${BOTPRESS_API_BASE}/files`, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${token}`,
      "x-bot-id": botId,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      key,
      size: buffer.byteLength,
      index: true,
      tags: {
        source: "knowledge-base",
        kbId,
        title
      }
    })
  });

  if (!createRes.ok) {
    const errorText = await createRes.text();
    throw new Error(`Botpress file create failed: ${createRes.status} ${errorText}`);
  }

  const createJson = await createRes.json();

  const uploadRes = await fetch(createJson.file.uploadUrl, {
    method: "PUT",
    body: buffer
  });

  if (!uploadRes.ok) {
    const errorText = await uploadRes.text();
    throw new Error(`Botpress file upload failed: ${uploadRes.status} ${errorText}`);
  }

  return {
    fileId: createJson.file.id,
    key,
    title
  };
}