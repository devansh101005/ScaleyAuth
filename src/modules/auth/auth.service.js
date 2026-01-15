import bcrypt from "bcrypt";
import prisma from "../../prisma/client.js";

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

  return {
    id: user.id,
    email: user.email
  };
};
