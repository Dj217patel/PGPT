function basicSummary(text: string): string {
  const cleaned = text.replace(/\s+/g, " ").trim();

  if (!cleaned) {
    return "No readable text found in the uploaded PDF.";
  }

  const clipped = cleaned.slice(0, 7000);
  const sentences = clipped
    .split(/(?<=[.!?])\s+/)
    .filter(Boolean)
    .slice(0, 20);

  return [
    "Document Summary",
    "",
    ...sentences
  ].join("\n");
}

export async function summarizeText(rawText: string): Promise<string> {
  const cleaned = rawText.replace(/\s+/g, " ").trim();

  if (!cleaned) {
    return "No readable text found in the uploaded PDF.";
  }

  return basicSummary(cleaned);
}