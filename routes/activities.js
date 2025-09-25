const express = require('express');
const router = express.Router();
const Activity = require('../models/Activity');
const auth = require('../middleware/auth');

router.get('/', auth, async (req, res) => {
  const activities = await Activity.find()
    .sort({ createdAt: -1 })
    .limit(50);
  res.json(activities);
});

module.exports = router;
