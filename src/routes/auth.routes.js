'use strict';

const { Router } = require('express');
const { register, login, refresh, logout } = require('../controllers/auth.controller');

const router = Router();

// POST /auth/register
router.post('/register', register);

// POST /auth/login
router.post('/login', login);

// POST /auth/refresh  — rotates refresh token
router.post('/refresh', refresh);

// POST /auth/logout   — revokes current session
router.post('/logout', logout);

module.exports = router;

