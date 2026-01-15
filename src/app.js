import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import swaggerUi from "swagger-ui-express";
import YAML from "yamljs";

import authRoutes from "./modules/auth/auth.routes.js";
import { errorHandler, notFoundHandler } from "./middlewares/errorHandler.js";
import { apiRateLimiter } from "./middlewares/rateLimiter.js";
import prisma from "./prisma/client.js";
import redisClient from "./config/redis.js";

const app = express();

// Trust proxy for rate limiting behind reverse proxy
if (process.env.NODE_ENV === "production") {
  app.set("trust proxy", 1);
}

// Security middleware
app.use(helmet());

// CORS configuration
app.use(cors({
  origin: process.env.CORS_ORIGIN?.split(",") || ["http://localhost:3000"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

// Request logging
if (process.env.NODE_ENV !== "test") {
  app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));
}

// Body parsing
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

// Global rate limiting
app.use(apiRateLimiter);

// Health check endpoint
app.get("/health", async (req, res) => {
  const health = {
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: {}
  };

  // Check database
  try {
    await prisma.$queryRaw`SELECT 1`;
    health.checks.database = "ok";
  } catch {
    health.checks.database = "error";
    health.status = "degraded";
  }

  // Check Redis
  try {
    await redisClient.ping();
    health.checks.redis = "ok";
  } catch {
    health.checks.redis = "error";
    health.status = "degraded";
  }

  const statusCode = health.status === "ok" ? 200 : 503;
  res.status(statusCode).json(health);
});

// API routes
app.use("/auth", authRoutes);

// Swagger documentation
try {
  const swaggerDoc = YAML.load("./swagger.yaml");
  app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerDoc, {
    customCss: ".swagger-ui .topbar { display: none }",
    customSiteTitle: "Auth Service API Documentation"
  }));
} catch (err) {
  console.warn("[Swagger] Failed to load documentation:", err.message);
}

// 404 handler
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

// Graceful shutdown
const gracefulShutdown = async (signal) => {
  console.log(`\n[Server] ${signal} received. Shutting down gracefully...`);

  try {
    await prisma.$disconnect();
    console.log("[Prisma] Disconnected");
  } catch (err) {
    console.error("[Prisma] Error disconnecting:", err.message);
  }

  process.exit(0);
};

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));

export default app;
