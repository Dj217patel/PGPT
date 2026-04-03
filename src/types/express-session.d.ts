import "express-session";

declare module "express-session" {
  interface SessionData {
    userId?: string;
    userEmail?: string;
    userRole?: "user" | "admin";
    mfaVerified?: boolean;
    mustEnrollMfa?: boolean;
    csrfSecret?: string;
  }
}
