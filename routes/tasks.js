const express = require('express');
const router = express.Router();
const Task = require('../models/Task');
const auth = require('../middleware/auth');
const { success, error } = require('../utils/apiResponse');

router.get('/', auth, async (req, res, next) => {
  try {
    const { parsePagination, buildMeta } = require('../utils/pagination');
    const { page, limit, skip } = parsePagination(req.query);

    const filter = {};
    if (req.query.projectId) filter.project = req.query.projectId;
    if (req.query.status) filter.status = req.query.status;
    if (req.query.assignedTo) filter.assignedTo = req.query.assignedTo;
    if (req.query.archived === 'true') filter.isArchived = true;
    if (req.query.archived === 'false') filter.isArchived = false;
    if (req.query.q) {
      // naive text search across title & description via regex (small scale). If large scale, use text index.
      const r = new RegExp(req.query.q, 'i');
      filter.$or = [{ title: r }, { description: r }];
    }

    const [items, total] = await Promise.all([
      Task.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Task.countDocuments(filter)
    ]);

    return res.json(success({ items, meta: buildMeta({ page, limit, total }) }));
  } catch (e) { return next(e); }
});

router.post('/', auth, async (req, res, next) => {
  try {
    const { title, description, project, assignedTo } = req.body;
    if (!title) return res.status(400).json(error('Title required'));
    const t = new Task({ title, description, project, assignedTo });
    await t.save();
    return res.status(201).json(success(t));
  } catch (e) { return next(e); }
});

// Partial update with optimistic version increment
router.patch('/:id', auth, async (req, res, next) => {
  try {
    const allowed = ['title', 'description', 'status', 'progress', 'assignee', 'assignedTo', 'project'];
    const patch = {};
    for (const k of allowed) if (k in req.body) patch[k] = req.body[k];
    if (Object.keys(patch).length === 0) return res.status(400).json(error('No valid fields to update'));

    // Normalize assignee field naming
    if (patch.assignedTo && !patch.assignee) patch.assignee = patch.assignedTo;
    delete patch.assignedTo;

    patch.updatedAt = new Date();
    // Increment version atomically
    const updated = await Task.findOneAndUpdate(
      { _id: req.params.id },
      { $set: patch, $inc: { version: 1 } },
      { new: true }
    );
    if (!updated) return res.status(404).json(error('Task not found'));
    return res.json(success(updated));
  } catch (e) { return next(e); }
});

module.exports = router;
