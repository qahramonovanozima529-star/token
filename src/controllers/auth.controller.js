'use strict';

const User = require('../models/User.model');
const RefreshSession = require('../models/RefreshSession.model');
const {
  signAccessToken,
  generateRefreshToken,
  hashRefreshToken,
  refreshTokenExpiresAt,
  refreshCookieOptions,
  clearCookieOptions,
} = require('../utils/token.utils');

// ─── Cookie name constant ─────────────────────────────────────────────────────
const REFRESH_COOKIE_NAME = 'refreshToken';

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/register
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Creates a new user account.
 * Returns 201 with the new user's public fields on success.
 */
const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: 'name, email and password are required.' });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ success: false, message: 'Password must be at least 8 characters.' });
    }

    // Check for duplicate email
    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res
        .status(409)
        .json({ success: false, message: 'Email already in use.' });
    }

    const passwordHash = await User.hashPassword(password);
    const user = await User.create({ name, email, passwordHash });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully.',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        createdAt: user.createdAt,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/login
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Authenticates a user.
 * - Returns an access token in JSON.
 * - Sets a httpOnly refresh token cookie.
 * - Persists a new RefreshSession document.
 */
const login = async (req, res, next) => {
  try {
    const { email, password, deviceName } = req.body;

    if (!email || !password || !deviceName) {
      return res
        .status(400)
        .json({ success: false, message: 'email, password and deviceName are required.' });
    }

    // Fetch user WITH passwordHash (select: false field)
    const user = await User.findOne({ email: email.toLowerCase().trim() }).select(
      '+passwordHash'
    );

    if (!user) {
      // Generic message — do not reveal whether email exists
      return res
        .status(401)
        .json({ success: false, message: 'Invalid credentials.' });
    }

    const passwordMatch = await user.comparePassword(password);
    if (!passwordMatch) {
      return res
        .status(401)
        .json({ success: false, message: 'Invalid credentials.' });
    }

    // ── Generate tokens ──────────────────────────────────────────────────────
    const accessToken = signAccessToken(user._id);
    const rawRefreshToken = generateRefreshToken();
    const refreshTokenHash = hashRefreshToken(rawRefreshToken);
    const expiresAt = refreshTokenExpiresAt();

    // ── Persist session ──────────────────────────────────────────────────────
    await RefreshSession.create({
      userId: user._id,
      refreshTokenHash,
      deviceName,
      ip: req.ip || null,
      expiresAt,
    });

    // ── Set cookie & respond ─────────────────────────────────────────────────
    res.cookie(REFRESH_COOKIE_NAME, rawRefreshToken, refreshCookieOptions());

    return res.status(200).json({
      success: true,
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/refresh
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Refresh Token Rotation:
 * 1. Read raw token from cookie.
 * 2. Hash it and find the matching active session in DB.
 * 3. Revoke old session (revokedAt = now).
 * 4. Issue new refresh token → new session.
 * 5. Return new access token in JSON.
 *
 * Security note: If the old token is not found (already revoked), it may
 * indicate token theft. We clear the cookie and return 401.
 */
const refresh = async (req, res, next) => {
  try {
    const rawToken = req.cookies[REFRESH_COOKIE_NAME];

    if (!rawToken) {
      return res
        .status(401)
        .json({ success: false, message: 'Refresh token not found.' });
    }

    const tokenHash = hashRefreshToken(rawToken);

    // Find an active, non-expired session matching this hash
    const session = await RefreshSession.findOne({
      refreshTokenHash: tokenHash,
      revokedAt: null,
      expiresAt: { $gt: new Date() },
    });

    if (!session) {
      // Clear cookie — token is invalid / already rotated / stolen
      res.clearCookie(REFRESH_COOKIE_NAME, clearCookieOptions());
      return res
        .status(401)
        .json({ success: false, message: 'Session invalid or expired. Please log in again.' });
    }

    // ── Revoke old session ───────────────────────────────────────────────────
    session.revokedAt = new Date();
    await session.save();

    // ── Issue new tokens ─────────────────────────────────────────────────────
    const newAccessToken = signAccessToken(session.userId);
    const newRawRefreshToken = generateRefreshToken();
    const newRefreshTokenHash = hashRefreshToken(newRawRefreshToken);
    const expiresAt = refreshTokenExpiresAt();

    // ── Create new session (same device) ────────────────────────────────────
    await RefreshSession.create({
      userId: session.userId,
      refreshTokenHash: newRefreshTokenHash,
      deviceName: session.deviceName,
      ip: req.ip || null,
      expiresAt,
    });

    // ── Rotate cookie ────────────────────────────────────────────────────────
    res.cookie(REFRESH_COOKIE_NAME, newRawRefreshToken, refreshCookieOptions());

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/logout
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Logs the user out of the current device:
 * 1. Finds the session by refresh token hash.
 * 2. Marks it as revoked.
 * 3. Clears the cookie.
 */
const logout = async (req, res, next) => {
  try {
    const rawToken = req.cookies[REFRESH_COOKIE_NAME];

    if (rawToken) {
      const tokenHash = hashRefreshToken(rawToken);

      // Revoke the matching active session (if it exists)
      await RefreshSession.findOneAndUpdate(
        { refreshTokenHash: tokenHash, revokedAt: null },
        { revokedAt: new Date() }
      );
    }

    res.clearCookie(REFRESH_COOKIE_NAME, clearCookieOptions());

    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    });
  } catch (err) {
    next(err);
  }
};

module.exports = { register, login, refresh, logout };

