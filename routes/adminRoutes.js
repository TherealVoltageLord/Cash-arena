const express = require('express');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireAdmin } = require('../middleware/adminMiddleware');
const {
  getDashboard,
  getTransactions,
  updateTransaction,
  getUsers,
  suspendUser,
  createTask,
  getStats
} = require('../controllers/adminController');

const router = express.Router();

router.get('/dashboard', authenticateToken, requireAdmin, getDashboard);
router.get('/transactions', authenticateToken, requireAdmin, getTransactions);
router.put('/transactions/:id', authenticateToken, requireAdmin, updateTransaction);
router.get('/users', authenticateToken, requireAdmin, getUsers);
router.put('/users/:id/suspend', authenticateToken, requireAdmin, suspendUser);
router.post('/tasks', authenticateToken, requireAdmin, createTask);
router.get('/stats', authenticateToken, requireAdmin, getStats);

module.exports = router;
