const express = require('express');
const { getDashboard } = require('../controllers/userController');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

router.get('/dashboard', authenticateToken, getDashboard);

module.exports = router;