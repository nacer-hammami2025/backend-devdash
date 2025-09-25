const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const auth = require('../middleware/auth');
const { validate } = require('../middleware/validate.js');
const { success, error } = require('../utils/apiResponse.js');
const { ProjectCreateSchema } = require('../docs/openapi.js');

router.get('/', auth, async (req, res, next) => {
  try {
    const { parsePagination, buildMeta } = require('../utils/pagination');
    const { page, limit, skip } = parsePagination(req.query);

    // Basic filters (optional): status, archived, q (text search)
    const filter = {};
    if (req.query.status) filter.status = req.query.status;
    if (req.query.archived === 'true') filter.isArchived = true;
    if (req.query.archived === 'false') filter.isArchived = false;
    if (req.query.q) filter.$text = { $search: req.query.q };

    const [items, total] = await Promise.all([
      Project.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      Project.countDocuments(filter)
    ]);

    return res.json(success({ items, meta: buildMeta({ page, limit, total }) }));
  } catch (e) { return next(e); }
});

router.post('/', auth, validate({ body: ProjectCreateSchema }), async (req, res, next) => {
  try {
    const { name, description, deadline, status, priority, tags } = req.validatedBody;
    const p = await Project.create({
      name,
      description,
      deadline,
      status: status || 'active',
      priority: priority || 'medium',
      tags: Array.isArray(tags) ? tags : [],
      createdBy: req.user.id
    });
    return res.status(201).json(success(p));
  } catch (err) { return next(err); }
});

router.get('/:id', auth, async (req, res, next) => {
  try {
    const p = await Project.findById(req.params.id);
    if (!p) return res.status(404).json(error('Not found'));
    return res.json(success(p));
  } catch (e) { return next(e); }
});

// Update a project
router.put('/:id', auth, async (req, res, next) => {
  try {
    const updates = {};
    const allowed = ['name', 'description', 'status', 'deadline', 'progress', 'priority', 'tags', 'isArchived'];
    for (const k of allowed) {
      if (k in req.body) updates[k] = req.body[k];
    }
    const p = await Project.findByIdAndUpdate(req.params.id, updates, { new: true, runValidators: true });
    if (!p) return res.status(404).json(error('Not found'));
    return res.json(success(p));
  } catch (err) { return next(err); }
});

router.delete('/:id', auth, async (req, res, next) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) return res.status(404).json(error('Projet non trouvé'));
    await Project.findByIdAndDelete(req.params.id);
    return res.json(success({ message: 'Projet supprimé avec succès' }));
  } catch (e) { return next(e); }
});

module.exports = router;
