import { ValidationError } from "./validation";

/** ASVS-style: min 12, upper, lower, digit, special */
export function assertPasswordPolicy(plain: string, fieldName = "Password"): void {
  if (typeof plain !== "string") {
    throw new ValidationError(`${fieldName} is required.`);
  }
  if (plain.length < 12) {
    throw new ValidationError(`${fieldName} must be at least 12 characters.`);
  }
  if (plain.length > 200) {
    throw new ValidationError(`${fieldName} is too long.`);
  }
  if (!/[A-Z]/.test(plain)) {
    throw new ValidationError(`${fieldName} must include an uppercase letter.`);
  }
  if (!/[a-z]/.test(plain)) {
    throw new ValidationError(`${fieldName} must include a lowercase letter.`);
  }
  if (!/\d/.test(plain)) {
    throw new ValidationError(`${fieldName} must include a digit.`);
  }
  if (!/[^A-Za-z0-9]/.test(plain)) {
    throw new ValidationError(`${fieldName} must include a special character.`);
  }
}
