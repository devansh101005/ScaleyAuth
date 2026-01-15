import axios from "axios";
import bcrypt from "bcrypt";
import crypto from "crypto";
import prisma from "../../prisma/client.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../../utils/token.js";
import { AppError } from "../../middlewares/errorHandler.js";
import redisClient from "../../config/redis.js";

const LOCK_TIME_MS = 15 * 60 * 1000; // 15 minutes
const MAX_LOGIN_ATTEMPTS = 5;
const SESSION_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

/**
 * Register a new user with email and password
 */
export const register = async ({ email, password }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const existingUser = await prisma.user.findUnique({
    where: { email: normalizedEmail }
  });

  if (existingUser) {
    throw new AppError("User already exists", 409);
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      email: normalizedEmail,
      passwordHash
    }
  });

  return {
    id: user.id,
    email: user.email
  };
};

/**
 * Authenticate user with email and password
 * Implements account lockout after MAX_LOGIN_ATTEMPTS failed attempts
 */
export const login = async ({ email, password }) => {
  const normalizedEmail = email.toLowerCase().trim();

  const user = await prisma.user.findUnique({
    where: { email: normalizedEmail },
    include: {
      userRoles: {
        include: { role: true }
      }
    }
  });

  // Prevent timing attacks by always hashing
  if (!user) {
    await bcrypt.hash("dummy-password-for-timing", 12);
    throw new AppError("Invalid credentials", 401);
  }

  // 1. Check if account is locked FIRST (before password check)
  if (user.lockUntil && user.lockUntil > new Date()) {
    const remainingMs = user.lockUntil.getTime() - Date.now();
    const remainingMin = Math.ceil(remainingMs / 60000);
    throw new AppError(`Account locked. Try again in ${remainingMin} minutes`, 423);
  }

  // 2. Validate password
  const isValid = await bcrypt.compare(password, user.passwordHash);

  // 3. Handle failed login attempt
  if (!isValid) {
    const attempts = user.failedLoginAttempts + 1;
    const shouldLock = attempts >= MAX_LOGIN_ATTEMPTS;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: attempts,
        lockUntil: shouldLock ? new Date(Date.now() + LOCK_TIME_MS) : null
      }
    });

    if (shouldLock) {
      throw new AppError("Too many failed attempts. Account locked for 15 minutes", 423);
    }

    throw new AppError("Invalid credentials", 401);
  }

  // 4. Reset failed attempts on successful login
  if (user.failedLoginAttempts > 0) {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockUntil: null
      }
    });
  }

  // 5. Generate tokens with full claims
  const roleNames = user.userRoles.map(ur => ur.role.name);

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    roles: roleNames
  });

  const refreshToken = signRefreshToken({
    sub: user.id
  });

  const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

  // 6. Create session
  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash,
      expiresAt: new Date(Date.now() + SESSION_EXPIRY_MS)
    }
  });

  return { accessToken, refreshToken };
};

/**
 * Refresh access token using refresh token
 * Implements token rotation for security
 */
export const refresh = async ({ refreshToken }) => {
  if (!refreshToken) {
    throw new AppError("Refresh token required", 401);
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch (err) {
    throw new AppError("Invalid or expired refresh token", 401);
  }

  // Fetch user's sessions only (not all sessions!)
  const sessions = await prisma.session.findMany({
    where: {
      userId: payload.sub,
      expiresAt: { gt: new Date() } // Only non-expired sessions
    }
  });

  let matchedSession = null;

  for (const session of sessions) {
    const match = await bcrypt.compare(refreshToken, session.refreshTokenHash);
    if (match) {
      matchedSession = session;
      break;
    }
  }

  // Refresh token reuse detected - revoke all sessions (potential theft)
  if (!matchedSession) {
    await prisma.session.deleteMany({
      where: { userId: payload.sub }
    });
    throw new AppError("Session invalidated. Please login again", 401);
  }

  // Rotate: delete old session
  await prisma.session.delete({
    where: { id: matchedSession.id }
  });

  // Fetch user for fresh claims
  const user = await prisma.user.findUnique({
    where: { id: payload.sub },
    include: {
      userRoles: {
        include: { role: true }
      }
    }
  });

  if (!user) {
    throw new AppError("User not found", 401);
  }

  // Issue new tokens with FULL claims (fixed: was missing email/roles)
  const roleNames = user.userRoles.map(ur => ur.role.name);

  const newAccessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    roles: roleNames
  });

  const newRefreshToken = signRefreshToken({
    sub: user.id
  });

  const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 12);

  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash: newRefreshTokenHash,
      expiresAt: new Date(Date.now() + SESSION_EXPIRY_MS)
    }
  });

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  };
};

/**
 * Logout user by invalidating their session
 * Optimized: filters by userId first instead of scanning all sessions
 */
export const logout = async ({ refreshToken }) => {
  if (!refreshToken) {
    return { success: true };
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    // Token invalid/expired, but logout should still succeed
    return { success: true };
  }

  // Only fetch THIS user's sessions (O(1) lookup by userId index)
  const sessions = await prisma.session.findMany({
    where: { userId: payload.sub }
  });

  for (const session of sessions) {
    const match = await bcrypt.compare(refreshToken, session.refreshTokenHash);
    if (match) {
      await prisma.session.delete({
        where: { id: session.id }
      });
      break;
    }
  }

  return { success: true };
};

/**
 * Generate OAuth state token for CSRF protection
 */
export const generateOAuthState = async () => {
  const state = crypto.randomBytes(32).toString("hex");
  // Store state in Redis with 10 minute expiry
  await redisClient.setEx(`oauth_state:${state}`, 600, "valid");
  return state;
};

/**
 * Verify OAuth state token
 */
export const verifyOAuthState = async (state) => {
  if (!state) return false;
  const result = await redisClient.get(`oauth_state:${state}`);
  if (result) {
    await redisClient.del(`oauth_state:${state}`); // Single use
    return true;
  }
  return false;
};

/**
 * Handle Google OAuth callback
 */
export const googleOAuth = async (code, state) => {
  // Verify state parameter to prevent CSRF
  const isValidState = await verifyOAuthState(state);
  if (!isValidState) {
    throw new AppError("Invalid OAuth state. Please try again", 400);
  }

  // 1. Exchange code for access token
  let tokenRes;
  try {
    tokenRes = await axios.post("https://oauth2.googleapis.com/token", {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: process.env.GOOGLE_CALLBACK_URL
    });
  } catch (err) {
    throw new AppError("Failed to exchange OAuth code", 400);
  }

  const { access_token } = tokenRes.data;

  // 2. Fetch user profile
  let profileRes;
  try {
    profileRes = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
      headers: { Authorization: `Bearer ${access_token}` }
    });
  } catch (err) {
    throw new AppError("Failed to fetch user profile", 400);
  }

  const { id: providerId, email } = profileRes.data;

  if (!email) {
    throw new AppError("Email not provided by OAuth provider", 400);
  }

  const normalizedEmail = email.toLowerCase().trim();

  // 3. Find or create/link user
  let user = await prisma.user.findFirst({
    where: {
      OR: [
        { provider: "google", providerId },
        { email: normalizedEmail }
      ]
    },
    include: {
      userRoles: {
        include: { role: true }
      }
    }
  });

  if (user) {
    // Link Google provider if user exists with same email but different provider
    if (user.provider !== "google") {
      user = await prisma.user.update({
        where: { id: user.id },
        data: {
          provider: "google",
          providerId,
          isVerified: true
        },
        include: {
          userRoles: {
            include: { role: true }
          }
        }
      });
    }
  } else {
    // Create new user
    user = await prisma.user.create({
      data: {
        email: normalizedEmail,
        passwordHash: "", // OAuth users don't have passwords
        provider: "google",
        providerId,
        isVerified: true
      },
      include: {
        userRoles: {
          include: { role: true }
        }
      }
    });
  }

  // 4. Issue tokens with full claims
  const roleNames = user.userRoles.map(ur => ur.role.name);

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    roles: roleNames
  });

  const refreshToken = signRefreshToken({
    sub: user.id
  });

  const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash,
      expiresAt: new Date(Date.now() + SESSION_EXPIRY_MS)
    }
  });

  return { accessToken, refreshToken };
};

/**
 * Cleanup expired sessions (call from cron job)
 */
export const cleanupExpiredSessions = async () => {
  const result = await prisma.session.deleteMany({
    where: {
      expiresAt: { lt: new Date() }
    }
  });
  return { deletedCount: result.count };
};
