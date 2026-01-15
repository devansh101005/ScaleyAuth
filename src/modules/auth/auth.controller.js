import * as authService from "./auth.service.js";
import { asyncHandler } from "../../middlewares/errorHandler.js";

export const register = asyncHandler(async (req, res) => {
  const user = await authService.register(req.body);
  res.status(201).json({
    success: true,
    data: user
  });
});

export const login = asyncHandler(async (req, res) => {
  const tokens = await authService.login(req.body);
  res.status(200).json({
    success: true,
    data: tokens
  });
});

export const refreshToken = asyncHandler(async (req, res) => {
  const tokens = await authService.refresh({
    refreshToken: req.body.refreshToken
  });
  res.status(200).json({
    success: true,
    data: tokens
  });
});

export const logout = asyncHandler(async (req, res) => {
  await authService.logout({
    refreshToken: req.body.refreshToken
  });
  res.status(200).json({
    success: true,
    message: "Logged out successfully"
  });
});

export const googleRedirect = asyncHandler(async (req, res) => {
  const state = await authService.generateOAuthState();

  const params = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: process.env.GOOGLE_CALLBACK_URL,
    response_type: "code",
    scope: "email profile",
    state,
    access_type: "offline",
    prompt: "consent"
  });

  const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  res.redirect(redirectUrl);
});

export const googleCallback = asyncHandler(async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`${process.env.FRONTEND_URL || "/"}/auth/error?error=${error}`);
  }

  const tokens = await authService.googleOAuth(code, state);

  // In production, set tokens in httpOnly cookies and redirect
  if (process.env.NODE_ENV === "production" && process.env.FRONTEND_URL) {
    res.cookie("accessToken", tokens.accessToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 10 * 60 * 1000 // 10 minutes
    });
    res.cookie("refreshToken", tokens.refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
    });
    return res.redirect(`${process.env.FRONTEND_URL}/auth/success`);
  }

  // Development: return tokens in response
  res.status(200).json({
    success: true,
    data: tokens
  });
});
