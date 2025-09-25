const express = require('express');
const router = express.Router();
const User = require('../models/User');
const auth = require('../middleware/auth');
const { success } = require('../utils/apiResponse');

router.get('/', auth, async (req, res, next) => {
  try {
    const { parsePagination, buildMeta } = require('../utils/pagination');
    const { page, limit, skip } = parsePagination(req.query);
    const filter = {};
    if (req.query.role) filter.role = req.query.role;
    if (req.query.q) {
      const r = new RegExp(req.query.q, 'i');
      filter.$or = [{ username: r }, { email: r }];
    }
    const [items, total] = await Promise.all([
      User.find(filter).select('-password').sort({ createdAt: -1 }).skip(skip).limit(limit),
      User.countDocuments(filter)
    ]);
    return res.json(success({ items, meta: buildMeta({ page, limit, total }) }));
  } catch (e) { return next(e); }
});

module.exports = router;
