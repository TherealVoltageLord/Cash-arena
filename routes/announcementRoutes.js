const express = require('express');
const { getActiveAnnouncements, createAnnouncement } = require('../controllers/announcementController');
const { authenticateToken } = require('../middleware/authMiddleware');
const { requireAdmin } = require('../middleware/adminMiddleware');
const router = express.Router();

router.get('/', getActiveAnnouncements);
router.post('/', authenticateToken, requireAdmin, createAnnouncement);

module.exports = router;
