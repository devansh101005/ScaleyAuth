import { Router } from "express";
import { register, login, googleRedirect, googleCallback, refreshToken, logout } from "./auth.controller.js";
import { loginRateLimiter, refreshRateLimiter } from "../../middlewares/rateLimiter.js";
import { validateRequest } from "../../middlewares/validation.middleware.js";
import { loginSchema, registerSchema, refreshSchema } from "./auth.validation.js";

const router = Router();

router.post("/register", validateRequest(registerSchema), register);
router.post("/login", loginRateLimiter, validateRequest(loginSchema), login);
router.post("/refresh", refreshRateLimiter, validateRequest(refreshSchema), refreshToken);
router.post("/logout", logout);
router.get("/google", googleRedirect);
router.get("/google/callback", googleCallback);

export default router;
