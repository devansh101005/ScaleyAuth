import { Router } from "express";
import { register, login } from "./auth.controller.js";

const router = Router();

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refreshToken);
router.post("/logout", logout);
router.get("/google", googleRedirect);
router.get("/google/callback", googleCallback);




export default router;
