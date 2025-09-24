const express = require('express');
const { completeTask } = require('../controllers/taskController');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/:taskId/complete', authenticateToken, completeTask);

module.exports = router;