'use strict';

const { Router } = require('express');
const authenticate = require('../middleware/authenticate');
const { getMe, getSessions, revokeSession } = require('../controllers/user.controller');

const router = Router();

// All routes below require a valid access token
router.use(authenticate);

// GET /me — current user profile
router.get('/me', getMe);

// GET /sessions — list all refresh sessions for the authenticated user
router.get('/sessions', getSessions);

// DELETE /sessions/:id — revoke (kick) a specific device session
router.delete('/sessions/:id', revokeSession);

module.exports = router;

