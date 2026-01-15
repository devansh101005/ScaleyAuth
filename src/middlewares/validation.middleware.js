import { AppError } from "./errorHandler.js";

/**
 * Request validation middleware using Zod schemas
 * @param {import('zod').ZodSchema} schema - Zod schema to validate against
 */
export const validateRequest = (schema) => {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const errors = result.error.errors.map((err) => ({
        field: err.path.join("."),
        message: err.message
      }));

      return res.status(400).json({
        success: false,
        error: {
          message: "Validation failed",
          details: errors
        }
      });
    }

    // Replace body with parsed/transformed data
    req.body = result.data;
    next();
  };
};

/**
 * Query parameter validation middleware
 * @param {import('zod').ZodSchema} schema - Zod schema to validate against
 */
export const validateQuery = (schema) => {
  return (req, res, next) => {
    const result = schema.safeParse(req.query);

    if (!result.success) {
      const errors = result.error.errors.map((err) => ({
        field: err.path.join("."),
        message: err.message
      }));

      return res.status(400).json({
        success: false,
        error: {
          message: "Invalid query parameters",
          details: errors
        }
      });
    }

    req.query = result.data;
    next();
  };
};

/**
 * URL parameter validation middleware
 * @param {import('zod').ZodSchema} schema - Zod schema to validate against
 */
export const validateParams = (schema) => {
  return (req, res, next) => {
    const result = schema.safeParse(req.params);

    if (!result.success) {
      const errors = result.error.errors.map((err) => ({
        field: err.path.join("."),
        message: err.message
      }));

      return res.status(400).json({
        success: false,
        error: {
          message: "Invalid URL parameters",
          details: errors
        }
      });
    }

    req.params = result.data;
    next();
  };
};
