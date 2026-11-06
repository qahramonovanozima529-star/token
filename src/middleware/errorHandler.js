'use strict';

/**
 * Global Express error handler.
 *
 * Catches errors forwarded via next(err).
 * - In development mode it exposes the stack trace.
 * - In production mode only a generic message is sent so internals are not leaked.
 *
 * Mongoose validation errors (err.name === 'ValidationError') are translated
 * into a 400 response with friendly field-level messages.
 */
const errorHandler = (err, req, res, next) => { // eslint-disable-line no-unused-vars
  // ── Mongoose validation error ────────────────────────────────────────────
  if (err.name === 'ValidationError') {
    const messages = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({
      success: false,
      message: 'Validation error.',
      errors: messages,
    });
  }

  // ── Mongoose duplicate key error ─────────────────────────────────────────
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue)[0];
    return res.status(409).json({
      success: false,
      message: `${field} already exists.`,
    });
  }

  // ── Default ──────────────────────────────────────────────────────────────
  const statusCode = err.statusCode || err.status || 500;
  const isDev = process.env.NODE_ENV === 'development';

  console.error(`[ERROR] ${req.method} ${req.url} →`, err);

  return res.status(statusCode).json({
    success: false,
    message: isDev ? err.message : 'Internal server error.',
    ...(isDev && { stack: err.stack }),
  });
};

module.exports = errorHandler;

