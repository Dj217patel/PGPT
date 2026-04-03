export interface UploadedKbFileResult {
  fileId: string;
  key: string;
  title: string;
  summaryText: string;
}

export interface AskRequestBody {
  question: string;
}

export interface ChatMessage {
  role: "user" | "assistant";
  message: string;
}