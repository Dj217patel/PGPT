import { Router } from "express";
import QRCode from "qrcode";
import {
  findUserByEmail,
  findUserById,
  createUser,
  updatePassword,
  checkPassword,
  setMfaEnabled,
  setTotpSecret
} from "./userService";
import {
  validateEmail,
  assertUtf8String,
  ValidationError
} from "../security/validation";
import { assertPasswordPolicy } from "../security/passwordPolicy";
import {
  encryptTotpForStorage,
  decryptTotpFromStorage,
  generateTotpSecret,
  otpAuthUrl,
  verifyTotpToken
} from "./mfa";
import { ensureCsrfSecret, createCsrfToken } from "../security/csrf";
import { strictAuthLimiter, authLimiter, mfaLimiter } from "../security/rateLimiters";
import {
  requireFullAuth,
  requireAuthenticatedPartial,
  requireFullAuthOrMfaEnrollment
} from "./authMiddleware";
import { logWarn } from "../logger";
import { csrfProtectionMiddleware } from "../security/csrf";

export const authRouter = Router();

authRouter.use((req, res, next) => {
  if (["POST", "PUT", "DELETE", "PATCH"].includes(req.method)) {
    return csrfProtectionMiddleware(req, res, next);
  }
  next();
});

authRouter.get("/csrf-token", authLimiter, (req, res) => {
  ensureCsrfSecret(req);
  res.json({ csrfToken: createCsrfToken(req) });
});

authRouter.get("/me", authLimiter, async (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ authenticated: false });
  }
  const row = await findUserById(req.session.userId);
  res.json({
    authenticated: true,
    user: {
      id: req.session.userId,
      email: req.session.userEmail,
      role: req.session.userRole,
      mustEnrollMfa: !!req.session.mustEnrollMfa,
      mfaVerified: !!req.session.mfaVerified,
      mfaEnabled: !!row?.mfa_enabled
    }
  });
});

authRouter.post("/register", strictAuthLimiter, async (req, res) => {
  try {
    if (process.env.ALLOW_PUBLIC_REGISTRATION === "false") {
      return res.status(403).json({ error: "Registration is disabled." });
    }
    const email = validateEmail(req.body.email);
    const password = assertUtf8String(req.body.password, "Password", 200);
    if (!password) {
      return res.status(400).json({ error: "Password is required." });
    }
    assertPasswordPolicy(password);
    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    const user = await createUser({ email, password, role: "user" });
    req.session.regenerate((err) => {
      if (err) {
        return res.status(500).json({ error: "Could not create session." });
      }
      ensureCsrfSecret(req);
      req.session.userId = user.id;
      req.session.userEmail = user.email;
      req.session.userRole = user.role;
      req.session.mustEnrollMfa = false;
      req.session.mfaVerified = true;
      res.json({ ok: true, next: "app" });
    });
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.message });
    }
    console.error("[REGISTER] unhandled error:", e);
    const message = e instanceof Error ? e.message : String(e);
    res.status(500).json({ error: "Registration failed.", message });
  }
});

function applyPostAuthSession(
  req: import("express").Request,
  user: import("./userService").UserRow,
  done: (err?: Error) => void
) {
  req.session.regenerate((err) => {
    if (err) {
      return done(err);
    }
    ensureCsrfSecret(req);
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.userRole = user.role;

    if (user.role === "admin" && !user.mfa_enabled) {
      req.session.mustEnrollMfa = true;
      req.session.mfaVerified = false;
    } else if (user.mfa_enabled) {
      req.session.mustEnrollMfa = false;
      req.session.mfaVerified = false;
    } else {
      req.session.mustEnrollMfa = false;
      req.session.mfaVerified = true;
    }
    done();
  });
}

authRouter.post("/login", strictAuthLimiter, async (req, res) => {
  try {
    const email = validateEmail(req.body.email);
    const password = assertUtf8String(req.body.password, "Password", 200);
    if (!password) {
      return res.status(400).json({ error: "Password is required." });
    }
    const user = await findUserByEmail(email);
    if (!user || !checkPassword(password, user.password_hash)) {
      logWarn("Failed login", { email });
      return res.status(401).json({ error: "Invalid email or password." });
    }

    applyPostAuthSession(req, user, (err) => {
      if (err) {
        return res.status(500).json({ error: "Session error." });
      }
      if (req.session.mustEnrollMfa) {
        return res.json({ ok: true, next: "mfa_enroll" });
      }
      if (!req.session.mfaVerified) {
        return res.json({ ok: true, next: "mfa_verify" });
      }
      res.json({ ok: true, next: "app" });
    });
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.message });
    }
    res.status(500).json({ error: "Login failed." });
  }
});

authRouter.post("/logout", authLimiter, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("pgpt.sid");
    res.json({ ok: true });
  });
});

authRouter.post("/mfa/verify-login", mfaLimiter, requireAuthenticatedPartial, async (req, res) => {
  try {
    const code = assertUtf8String(req.body.code, "Code", 16);
    if (!code) {
      return res.status(400).json({ error: "Code is required." });
    }
    const user = await findUserById(req.session.userId!);
    if (!user?.mfa_enabled || !user.totp_secret) {
      return res.status(400).json({ error: "MFA is not enabled for this account." });
    }
    const secret = decryptTotpFromStorage(user.totp_secret);
    if (!verifyTotpToken(secret, code)) {
      return res.status(401).json({ error: "Invalid verification code." });
    }
    req.session.mfaVerified = true;
    if (user.role === "admin") {
      req.session.mustEnrollMfa = false;
    }
    res.json({ ok: true, next: "app" });
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.message });
    }
    res.status(500).json({ error: "MFA verification failed." });
  }
});

authRouter.post("/mfa/enroll/start", mfaLimiter, requireFullAuthOrMfaEnrollment, async (req, res) => {
  try {
    const u = await findUserById(req.session.userId!);
    if (!u) {
      return res.status(401).json({ error: "Invalid session." });
    }
    if (u.mfa_enabled) {
      return res.status(400).json({ error: "MFA is already enabled." });
    }
    if (req.session.userRole === "user" && req.session.mustEnrollMfa) {
      return res.status(400).json({ error: "Invalid state." });
    }
    const secret = generateTotpSecret();
    const url = otpAuthUrl(u.email, secret);
    const qrDataUrl = await QRCode.toDataURL(url);
    (req.session as unknown as { pendingTotp?: string }).pendingTotp = secret;
    res.json({ otpauthUrl: url, qrDataUrl });
  } catch {
    res.status(500).json({ error: "Could not start MFA enrollment." });
  }
});

authRouter.post("/mfa/enroll/confirm", mfaLimiter, requireFullAuthOrMfaEnrollment, async (req, res) => {
  try {
    const code = assertUtf8String(req.body.code, "Code", 16);
    if (!code) {
      return res.status(400).json({ error: "Code is required." });
    }
    const pending = (req.session as unknown as { pendingTotp?: string }).pendingTotp;
    if (!pending) {
      return res.status(400).json({ error: "Start MFA enrollment first." });
    }
    if (!verifyTotpToken(pending, code)) {
      return res.status(401).json({ error: "Invalid verification code." });
    }
    const enc = encryptTotpForStorage(pending);
    await setTotpSecret(req.session.userId!, enc);
    await setMfaEnabled(req.session.userId!, true);
    delete (req.session as unknown as { pendingTotp?: string }).pendingTotp;
    req.session.mustEnrollMfa = false;
    req.session.mfaVerified = true;
    res.json({ ok: true, next: "app" });
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.message });
    }
    res.status(500).json({ error: "MFA enrollment failed." });
  }
});

authRouter.post("/change-password", authLimiter, requireFullAuth, async (req, res) => {
  try {
    const current = assertUtf8String(req.body.currentPassword, "Current password", 200);
    const nextPwd = assertUtf8String(req.body.newPassword, "New password", 200);
    if (!current || !nextPwd) {
      return res.status(400).json({ error: "Passwords are required." });
    }
    assertPasswordPolicy(nextPwd, "New password");
    const user = await findUserById(req.session.userId!);
    if (!user || !checkPassword(current, user.password_hash)) {
      return res.status(401).json({ error: "Current password is incorrect." });
    }
    await updatePassword(user.id, nextPwd);
    res.json({ ok: true });
  } catch (e) {
    if (e instanceof ValidationError) {
      return res.status(400).json({ error: e.message });
    }
    res.status(500).json({ error: "Could not change password." });
  }
});
