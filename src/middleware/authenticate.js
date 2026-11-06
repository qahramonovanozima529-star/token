'use strict';

const User = require('../models/User.model');
const { verifyAccessToken } = require('../utils/token.utils');

/**
 * Authentication middleware.
 *
 * Expects:  Authorization: Bearer <accessToken>
 *
 * On success  → populates req.user with the full User document and calls next().
 * On failure  → returns 401 immediately (never calls next with an error so
 *               a subsequent error handler cannot accidentally expose internals).
 */
const authenticate = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res
        .status(401)
        .json({ success: false, message: 'Access token missing.' });
    }

    const token = authHeader.split(' ')[1];

    // jwt.verify throws if token is expired or tampered
    const payload = verifyAccessToken(token);

    // Fetch the user to ensure they still exist in DB
    const user = await User.findById(payload.sub);
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: 'User no longer exists.' });
    }

    req.user = user;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res
        .status(401)
        .json({ success: false, message: 'Access token expired.' });
    }
    return res
      .status(401)
      .json({ success: false, message: 'Access token invalid.' });
  }
};

module.exports = authenticate;

