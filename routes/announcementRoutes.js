const express = require('express');
const { authenticateToken } = require('../middleware/authMiddleware');
const router = express.Router();

const announcementController = require('../controllers/announcementController');

router.get('/', announcementController.getActiveAnnouncements);
router.post('/', authenticateToken, announcementController.createAnnouncement);

module.exports = router;