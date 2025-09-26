const express = require('express');
const { claimDaily } = require('../controllers/rewardController');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/claim-daily', authenticateToken, claimDaily);

module.exports = router;
