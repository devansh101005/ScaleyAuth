import axios from "axios";
import bcrypt from "bcrypt";
import prisma from "../../prisma/client.js";
import { signAccessToken, signRefreshToken, verifyRefreshToken } from "../../utils/token.js";


export const register = async ({ email, password }) => {
  if (!email || !password) {
    throw new Error("Invalid input");
  }

  const existingUser = await prisma.user.findUnique({
    where: { email }
  });

  if (existingUser) {
    throw new Error("User already exists");
  }

  const passwordHash = await bcrypt.hash(password, 12);

  const user = await prisma.user.create({
    data: {
      email,
      passwordHash
    }
  });

  return {
    id: user.id,
    email: user.email
  };
};

export const login = async ({ email, password }) => {
  const user = await prisma.user.findUnique({
    where: { email }
  });

  if (!user) {
    throw new Error("Invalid credentials");
  }

  const isValid = await bcrypt.compare(password, user.passwordHash);

  if (!isValid) {
    throw new Error("Invalid credentials");
  }

  const roles = await prisma.userRole.findMany({
  where: { userId: user.id },
  include: { role: true }
});

const roleNames = roles.map(r => r.role.name);

  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email,
    roles: roleNames
  });

  const refreshToken = signRefreshToken({
    sub: user.id,
  });

 const refreshTokenHash = await bcrypt.hash(refreshToken, 12);


 await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });


  return {
    accessToken, refreshToken
  };

};

export const refresh = async ({ refreshToken }) => {
  if (!refreshToken) {
    throw new Error("Unauthorized");
  }

  let payload;
  try {
    payload = verifyRefreshToken(refreshToken);
  } catch {
    throw new Error("Unauthorized");
  }

  const sessions = await prisma.session.findMany({
    where: { userId: payload.sub }
  });

  let matchedSession = null;

  for (const session of sessions) {
    const match = await bcrypt.compare(
      refreshToken,
      session.refreshTokenHash
    );
    if (match) {
      matchedSession = session;
      break;
    }
  }

  //  Refresh token reuse detected
  if (!matchedSession) {
    await prisma.session.deleteMany({
      where: { userId: payload.sub }
    });
    throw new Error("Refresh token reuse detected");
  }

  // Rotate: delete old session
  await prisma.session.delete({
    where: { id: matchedSession.id }
  });

  // Issue new tokens
  const newAccessToken = signAccessToken({
    sub: payload.sub
  });

  const newRefreshToken = signRefreshToken({
    sub: payload.sub
  });

  const newRefreshTokenHash = await bcrypt.hash(newRefreshToken, 12);

  await prisma.session.create({
    data: {
      userId: payload.sub,
      refreshTokenHash: newRefreshTokenHash,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  };
};

export const logout = async ({ refreshToken }) => {
  if (!refreshToken) return;

  const sessions = await prisma.session.findMany();

  for (const session of sessions) {
    const match = await bcrypt.compare(
      refreshToken,
      session.refreshTokenHash
    );
    if (match) {
      await prisma.session.delete({
        where: { id: session.id }
      });
      break;
    }
  }
};



export const googleOAuth = async (code) => {
  // 1. Exchange code for access token
  const tokenRes = await axios.post(
    "https://oauth2.googleapis.com/token",
    {
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      code,
      grant_type: "authorization_code",
      redirect_uri: process.env.GOOGLE_CALLBACK_URL
    }
  );

  const { access_token } = tokenRes.data;

  // 2. Fetch user profile
  const profileRes = await axios.get(
    "https://www.googleapis.com/oauth2/v2/userinfo",
    {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    }
  );

  const { id, email } = profileRes.data;

  // 3. Find or create user
  let user = await prisma.user.findFirst({
    where: {
      provider: "google",
      providerId: id
    }
  });

  if (!user) {
    user = await prisma.user.create({
      data: {
        email,
        provider: "google",
        providerId: id,
        isVerified: true
      }
    });
  }

  // 4. Issue tokens (same as normal login)
  const accessToken = signAccessToken({
    sub: user.id,
    email: user.email
  });

  const refreshToken = signRefreshToken({
    sub: user.id
  });

  const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

  await prisma.session.create({
    data: {
      userId: user.id,
      refreshTokenHash,
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  return { accessToken, refreshToken };
};



