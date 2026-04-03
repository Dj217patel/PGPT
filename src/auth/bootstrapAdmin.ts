import { countAdmins, createUser, findUserByEmail } from "./userService";
import { assertPasswordPolicy } from "../security/passwordPolicy";
import { logInfo, logWarn } from "../logger";

export async function ensureBootstrapAdmin(): Promise<void> {
  const emailRaw = process.env.BOOTSTRAP_ADMIN_EMAIL;
  const password = process.env.BOOTSTRAP_ADMIN_PASSWORD;
  if (!emailRaw || !password) {
    return;
  }
  const email = emailRaw.toLowerCase().trim();
  try {
    assertPasswordPolicy(password);
  } catch {
    logWarn("BOOTSTRAP_ADMIN_PASSWORD does not meet policy; skipping bootstrap.");
    return;
  }
  const existing = await findUserByEmail(email);
  if (existing) {
    return;
  }
  const admins = await countAdmins();
  if (admins > 0) {
    return;
  }
  await createUser({ email, password, role: "admin" });
  logInfo("Bootstrap admin user created.");
}
