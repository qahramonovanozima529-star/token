'use strict';

const mongoose = require('mongoose');

/**
 * RefreshSession schema.
 *
 * One document = one active device session.
 * - refreshTokenHash : SHA-256 hash of the raw refresh token (never stored plain).
 * - revokedAt        : null means session is active; a Date means it was revoked.
 */
const refreshSessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: true,
      index: true,
    },
    refreshTokenHash: {
      type: String,
      required: true,
      // No index by default — lookup is by userId first, then we compare hashes
    },
    deviceName: {
      type: String,
      required: [true, 'deviceName is required'],
      trim: true,
      maxlength: [100, 'deviceName must be at most 100 characters'],
    },
    ip: {
      type: String,
      default: null,
    },
    expiresAt: {
      type: Date,
      required: true,
    },
    revokedAt: {
      type: Date,
      default: null, // null = session is active
    },
  },
  { timestamps: true }
);

// ─── Compound index for fast session lookup by user ───────────────────────────
refreshSessionSchema.index({ userId: 1, revokedAt: 1 });

// ─── TTL index: MongoDB auto-deletes expired sessions ─────────────────────────
// Documents are deleted ~60 s after their expiresAt timestamp.
refreshSessionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// ─── Virtual: is the session currently active? ────────────────────────────────
refreshSessionSchema.virtual('isActive').get(function () {
  return this.revokedAt === null && this.expiresAt > new Date();
});

const RefreshSession = mongoose.model('RefreshSession', refreshSessionSchema);

module.exports = RefreshSession;

