/**
 * Custom error class with HTTP status code support
 */
export class AppError extends Error {
  constructor(message, statusCode = 500, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date().toISOString();

    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Async handler wrapper to catch errors in async route handlers
 */
export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * 404 Not Found handler
 */
export const notFoundHandler = (req, res, next) => {
  next(new AppError(`Route ${req.method} ${req.originalUrl} not found`, 404));
};

/**
 * Global error handler middleware
 */
export const errorHandler = (err, req, res, next) => {
  // Default values
  let statusCode = err.statusCode || 500;
  let message = err.message || "Internal server error";
  let isOperational = err.isOperational || false;

  // Handle specific error types
  if (err.name === "JsonWebTokenError") {
    statusCode = 401;
    message = "Invalid token";
    isOperational = true;
  }

  if (err.name === "TokenExpiredError") {
    statusCode = 401;
    message = "Token expired";
    isOperational = true;
  }

  if (err.name === "ValidationError") {
    statusCode = 400;
    message = err.message;
    isOperational = true;
  }

  // Prisma errors
  if (err.code === "P2002") {
    statusCode = 409;
    message = "Resource already exists";
    isOperational = true;
  }

  if (err.code === "P2025") {
    statusCode = 404;
    message = "Resource not found";
    isOperational = true;
  }

  // Log error (in production, send to logging service)
  if (!isOperational || statusCode >= 500) {
    console.error(`[ERROR] ${new Date().toISOString()}`, {
      message: err.message,
      stack: err.stack,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip
    });
  }

  // Send response
  const response = {
    success: false,
    error: {
      message,
      ...(process.env.NODE_ENV === "development" && {
        stack: err.stack,
        code: err.code
      })
    }
  };

  res.status(statusCode).json(response);
};
