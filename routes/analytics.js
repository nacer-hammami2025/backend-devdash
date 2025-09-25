const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const analyticsController = require('../controllers/analyticsController');

// /api/analytics/trends
router.get('/trends', auth, analyticsController.getTrends);

module.exports = router;
