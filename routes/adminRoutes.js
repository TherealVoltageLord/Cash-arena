const express = require('express');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireAdmin } = require('../middleware/adminMiddleware');
const router = express.Router();

const adminController = require('../controllers/adminController');

router.get('/dashboard', authenticateToken, requireAdmin, adminController.getDashboard);
router.get('/transactions', authenticateToken, requireAdmin, adminController.getTransactions);
router.put('/transactions/:id', authenticateToken, requireAdmin, adminController.updateTransaction);
router.get('/users', authenticateToken, requireAdmin, adminController.getUsers);
router.put('/users/:id/suspend', authenticateToken, requireAdmin, adminController.suspendUser);
router.post('/tasks', authenticateToken, requireAdmin, adminController.createTask);
router.get('/stats', authenticateToken, requireAdmin, adminController.getStats);

module.exports = router;