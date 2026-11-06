'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// ─── Constants ────────────────────────────────────────────────────────────────
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN || '15m';
const REFRESH_TOKEN_EXPIRES_IN_DAYS =
  parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS, 10) || 7;

if (!ACCESS_TOKEN_SECRET || !REFRESH_TOKEN_SECRET) {
  throw new Error(
    'ACCESS_TOKEN_SECRET and REFRESH_TOKEN_SECRET must be set in environment variables.'
  );
}

// ─── Access Token ─────────────────────────────────────────────────────────────

/**
 * Signs and returns a JWT access token.
 * Payload contains only the user id (sub) to keep the token lean.
 * @param {string|ObjectId} userId
 * @returns {string} signed JWT
 */
const signAccessToken = (userId) => {
  return jwt.sign({ sub: userId.toString() }, ACCESS_TOKEN_SECRET, {
    expiresIn: ACCESS_TOKEN_EXPIRES_IN,
    algorithm: 'HS256',
  });
};

/**
 * Verifies a JWT access token and returns its decoded payload.
 * @param {string} token
 * @returns {{ sub: string, iat: number, exp: number }}
 * @throws {JsonWebTokenError | TokenExpiredError}
 */
const verifyAccessToken = (token) => {
  return jwt.verify(token, ACCESS_TOKEN_SECRET, { algorithms: ['HS256'] });
};

// ─── Refresh Token ────────────────────────────────────────────────────────────

/**
 * Generates a cryptographically secure random refresh token (hex string, 64 bytes).
 * This raw value is sent to the client via cookie.
 * It is NEVER persisted directly — only its hash is stored in the DB.
 * @returns {string} 128-char hex string
 */
const generateRefreshToken = () => {
  return crypto.randomBytes(64).toString('hex');
};

/**
 * Hashes a raw refresh token with SHA-256.
 * Used for DB storage and lookup (compare-by-hash pattern).
 * @param {string} rawToken
 * @returns {string} hex SHA-256 digest
 */
const hashRefreshToken = (rawToken) => {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
};

/**
 * Returns the Date at which a new refresh token will expire.
 * @returns {Date}
 */
const refreshTokenExpiresAt = () => {
  const d = new Date();
  d.setDate(d.getDate() + REFRESH_TOKEN_EXPIRES_IN_DAYS);
  return d;
};

// ─── Cookie Options ───────────────────────────────────────────────────────────

/**
 * Cookie options for the refresh token cookie.
 * - httpOnly  : JS cannot read it (XSS mitigation).
 * - sameSite  : 'strict' prevents CSRF.
 * - secure    : only sent over HTTPS in production.
 * - maxAge    : aligned with token expiry (ms).
 */
const refreshCookieOptions = () => ({
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
  maxAge: REFRESH_TOKEN_EXPIRES_IN_DAYS * 24 * 60 * 60 * 1000,
});

/**
 * Cookie options used when clearing the refresh token cookie.
 */
const clearCookieOptions = () => ({
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production',
});

module.exports = {
  signAccessToken,
  verifyAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  refreshTokenExpiresAt,
  refreshCookieOptions,
  clearCookieOptions,
};

