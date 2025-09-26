const express = require('express');
const { getTasks, completeTask } = require('../controllers/taskController');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

router.get('/', authenticateToken, getTasks);
router.post('/:taskId/complete', authenticateToken, completeTask);

module.exports = router;
