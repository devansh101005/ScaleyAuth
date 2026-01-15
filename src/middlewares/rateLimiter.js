import rateLimit from "express-rate-limit";
import RedisStore from "rate-limit-redis";
import redisClient from "../config/redis.js";

/**
 * Rate limiter for login attempts
 * 5 attempts per minute per IP
 */
export const loginRateLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args)
  }),
  windowMs: 60 * 1000, // 1 minute
  max: 5,
  message: {
    success: false,
    error: {
      message: "Too many login attempts. Please try again later."
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Rate limiter for refresh token endpoint
 * 10 attempts per minute per IP
 */
export const refreshRateLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args)
  }),
  windowMs: 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: {
      message: "Too many refresh requests. Please try again later."
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Rate limiter for registration
 * 3 registrations per hour per IP
 */
export const registerRateLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args)
  }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3,
  message: {
    success: false,
    error: {
      message: "Too many registration attempts. Please try again later."
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * General API rate limiter
 * 100 requests per minute per IP
 */
export const apiRateLimiter = rateLimit({
  store: new RedisStore({
    sendCommand: (...args) => redisClient.sendCommand(args)
  }),
  windowMs: 60 * 1000,
  max: 100,
  message: {
    success: false,
    error: {
      message: "Too many requests. Please slow down."
    }
  },
  standardHeaders: true,
  legacyHeaders: false
});
