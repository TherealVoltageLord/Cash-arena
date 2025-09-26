const express = require('express');
const { deposit, withdraw, getTransactions } = require('../controllers/transactionController');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

router.post('/deposit', authenticateToken, deposit);
router.post('/withdraw', authenticateToken, withdraw);
router.get('/', authenticateToken, getTransactions);

module.exports = router;
