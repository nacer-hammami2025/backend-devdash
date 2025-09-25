import { Router } from 'express';
import { auth } from '../middleware/auth.js';
import { Activity, Task } from '../models/index.js';
import { recalculateProjectProgress } from './projects.js';

const router = Router();

// Helper pour journaliser les activités
const logActivity = async (userId, action, taskId, details, req) => {
  try {
    await Activity.create({
      user: userId,
      action,
      target: 'task',
      targetId: taskId,
      details,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

// Helper pour calculer la progression selon le statut
const getProgressFromStatus = (status) => {
  const progressMap = {
    todo: 0,
    doing: 33,
    review: 66,
    done: 100
  };
  return progressMap[status] || 0;
};

// Récupérer toutes les tâches
router.get('/', auth, async (req, res) => {
  try {
    const { project, status, assignee } = req.query;
    const query = {};

    if (project) query.project = project;
    if (status) query.status = status;
    if (assignee) query.assignee = assignee;

    const tasks = await Task.find(query)
      .populate('project', 'name')
      .populate('assignee', 'name email')
      .sort({ createdAt: -1 });

    res.json(tasks);
  } catch (error) {
    console.error('Tasks fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch tasks',
      message: error.message || 'Internal server error'
    });
  }
});

// Récupérer une tâche par ID
router.get('/:id', auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id)
      .populate('project', 'name')
      .populate('assignee', 'name email');

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'The requested task does not exist'
      });
    }

    res.json(task);
  } catch (error) {
    console.error('Task fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch task',
      message: error.message || 'Internal server error'
    });
  }
});

// Créer une nouvelle tâche
router.post('/', auth, async (req, res) => {
  try {
    const { title, description, project, assignee } = req.body;

    const task = await Task.create({
      title,
      description,
      project,
      assignee,
      status: 'todo',
      progress: getProgressFromStatus('todo')
    });

    await logActivity(req.user.id, 'task.create', task._id, `Created task: ${title}`, req);

    // Mettre à jour la progression du projet
    await recalculateProjectProgress(project);

    res.status(201).json(task);
  } catch (error) {
    console.error('Task creation error:', error);
    res.status(500).json({
      error: 'Failed to create task',
      message: error.message || 'Internal server error'
    });
  }
});

// Mettre à jour une tâche
router.patch('/:id', auth, async (req, res) => {
  try {
    const { title, description, assignee, status } = req.body;
    const updates = {};

    if (title) updates.title = title;
    if (description) updates.description = description;
    if (assignee) updates.assignee = assignee;

    if (status && ['todo', 'doing', 'review', 'done'].includes(status)) {
      updates.status = status;
      updates.progress = getProgressFromStatus(status);
    }

    const task = await Task.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    ).populate('project', 'name');

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'The requested task does not exist'
      });
    }

    await logActivity(req.user.id, 'task.update', task._id,
      `Updated task: ${task.title} (Status: ${task.status})`, req);

    // Mettre à jour la progression du projet
    await recalculateProjectProgress(task.project._id);

    res.json(task);
  } catch (error) {
    console.error('Task update error:', error);
    res.status(500).json({
      error: 'Failed to update task',
      message: error.message || 'Internal server error'
    });
  }
});

// Supprimer une tâche
router.delete('/:id', auth, async (req, res) => {
  try {
    const task = await Task.findById(req.params.id);

    if (!task) {
      return res.status(404).json({
        error: 'Task not found',
        message: 'The requested task does not exist'
      });
    }

    const projectId = task.project;

    // Supprimer la tâche
    await Task.findByIdAndDelete(req.params.id);

    await logActivity(req.user.id, 'task.delete', task._id,
      `Deleted task: ${task.title}`, req);

    // Mettre à jour la progression du projet
    await recalculateProjectProgress(projectId);

    res.status(204).end();
  } catch (error) {
    console.error('Task deletion error:', error);
    res.status(500).json({
      error: 'Failed to delete task',
      message: error.message || 'Internal server error'
    });
  }
});

export default router;
