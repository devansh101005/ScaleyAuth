import { verifyAccessToken } from "../utils/token.js";

export const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const payload = verifyAccessToken(token);
    req.user = payload; // attach identity
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
