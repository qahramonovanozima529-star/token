'use strict';

const RefreshSession = require('../models/RefreshSession.model');

// ─────────────────────────────────────────────────────────────────────────────
// GET /me
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Returns the authenticated user's public profile.
 * req.user is populated by the `authenticate` middleware.
 */
const getMe = (req, res) => {
  const { _id, name, email, createdAt } = req.user;
  return res.status(200).json({
    success: true,
    user: { id: _id, name, email, createdAt },
  });
};

// ─────────────────────────────────────────────────────────────────────────────
// GET /sessions
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Lists all refresh sessions belonging to the authenticated user.
 * Returns only safe fields: deviceName, createdAt, revokedAt.
 * Sessions are sorted newest-first.
 */
const getSessions = async (req, res, next) => {
  try {
    const sessions = await RefreshSession.find(
      { userId: req.user._id },
      { deviceName: 1, createdAt: 1, revokedAt: 1, expiresAt: 1, _id: 1 }
    ).sort({ createdAt: -1 });

    return res.status(200).json({
      success: true,
      count: sessions.length,
      sessions,
    });
  } catch (err) {
    next(err);
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /sessions/:id
// ─────────────────────────────────────────────────────────────────────────────
/**
 * Revokes a specific session (remote logout / "kick device").
 * - Only the owner can revoke their own sessions.
 * - Already revoked sessions return 400.
 */
const revokeSession = async (req, res, next) => {
  try {
    const { id } = req.params;

    // Validate ObjectId format to avoid CastError
    if (!id.match(/^[a-f\d]{24}$/i)) {
      return res
        .status(400)
        .json({ success: false, message: 'Invalid session id.' });
    }

    const session = await RefreshSession.findOne({
      _id: id,
      userId: req.user._id, // ownership check
    });

    if (!session) {
      return res
        .status(404)
        .json({ success: false, message: 'Session not found.' });
    }

    if (session.revokedAt !== null) {
      return res
        .status(400)
        .json({ success: false, message: 'Session is already revoked.' });
    }

    session.revokedAt = new Date();
    await session.save();

    return res.status(200).json({
      success: true,
      message: 'Session revoked successfully.',
    });
  } catch (err) {
    next(err);
  }
};

module.exports = { getMe, getSessions, revokeSession };

