import { z } from "zod";

/**
 * Password requirements:
 * - Minimum 8 characters
 * - At least one uppercase letter
 * - At least one lowercase letter
 * - At least one number
 * - At least one special character
 */
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password must be less than 128 characters")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[a-z]/, "Password must contain at least one lowercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(/[^A-Za-z0-9]/, "Password must contain at least one special character");

/**
 * Email validation
 */
const emailSchema = z
  .string()
  .email("Invalid email format")
  .max(255, "Email must be less than 255 characters")
  .transform((val) => val.toLowerCase().trim());

/**
 * Registration request schema
 */
export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema
});

/**
 * Login request schema
 */
export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required")
});

/**
 * Refresh token request schema
 */
export const refreshSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token is required")
});

/**
 * Logout request schema
 */
export const logoutSchema = z.object({
  refreshToken: z.string().optional()
});

/**
 * Change password schema
 */
export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: passwordSchema
}).refine(
  (data) => data.currentPassword !== data.newPassword,
  {
    message: "New password must be different from current password",
    path: ["newPassword"]
  }
);

/**
 * Reset password request schema
 */
export const resetPasswordRequestSchema = z.object({
  email: emailSchema
});

/**
 * Reset password confirm schema
 */
export const resetPasswordConfirmSchema = z.object({
  token: z.string().min(1, "Reset token is required"),
  newPassword: passwordSchema
});
