'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12;

/**
 * User schema.
 * passwordHash is never sent back to the client (select: false).
 */
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'Name is required'],
      trim: true,
      maxlength: [80, 'Name must be at most 80 characters'],
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, 'Please enter a valid email'],
    },
    passwordHash: {
      type: String,
      required: true,
      select: false, // never returned in queries by default
    },
  },
  { timestamps: true }
);

// ─── Instance Methods ─────────────────────────────────────────────────────────

/**
 * Compares a plain-text password against the stored hash.
 * @param {string} plainPassword
 * @returns {Promise<boolean>}
 */
userSchema.methods.comparePassword = function (plainPassword) {
  return bcrypt.compare(plainPassword, this.passwordHash);
};

// ─── Static Methods ───────────────────────────────────────────────────────────

/**
 * Hashes a plain-text password.
 * @param {string} plainPassword
 * @returns {Promise<string>} bcrypt hash
 */
userSchema.statics.hashPassword = function (plainPassword) {
  return bcrypt.hash(plainPassword, SALT_ROUNDS);
};

const User = mongoose.model('User', userSchema);

module.exports = User;

