import "dotenv/config";
import app from "./app.js";

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`[Server] Running on port ${PORT}`);
  console.log(`[Server] Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`[Server] Health check: http://localhost:${PORT}/health`);
  console.log(`[Server] API docs: http://localhost:${PORT}/docs`);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  console.error("[Server] Unhandled Rejection at:", promise, "reason:", reason);
});

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("[Server] Uncaught Exception:", error);
  // Give time to log, then exit
  setTimeout(() => {
    process.exit(1);
  }, 1000);
});

export default server;
