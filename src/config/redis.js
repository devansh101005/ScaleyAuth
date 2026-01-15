import { createClient } from "redis";

const redisClient = createClient({
  url: process.env.REDIS_URL || "redis://localhost:6379",
  socket: {
    reconnectStrategy: (retries) => {
      if (retries > 10) {
        console.error("[Redis] Max reconnection attempts reached");
        return new Error("Max reconnection attempts reached");
      }
      // Exponential backoff: 100ms, 200ms, 400ms, etc.
      return Math.min(retries * 100, 3000);
    }
  }
});

redisClient.on("error", (err) => {
  console.error("[Redis] Connection error:", err.message);
});

redisClient.on("connect", () => {
  console.log("[Redis] Connected successfully");
});

redisClient.on("reconnecting", () => {
  console.log("[Redis] Reconnecting...");
});

// Connect with error handling
(async () => {
  try {
    await redisClient.connect();
  } catch (err) {
    console.error("[Redis] Initial connection failed:", err.message);
    // Don't crash the app - rate limiting will fall back to memory store
  }
})();

// Graceful shutdown
process.on("SIGTERM", async () => {
  console.log("[Redis] Closing connection...");
  await redisClient.quit();
});

process.on("SIGINT", async () => {
  console.log("[Redis] Closing connection...");
  await redisClient.quit();
});

export default redisClient;
