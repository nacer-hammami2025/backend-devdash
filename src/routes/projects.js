import { Router } from 'express';
import { admin } from '../middleware/admin.js';
import { auth } from '../middleware/auth.js';
import { Activity, Project, Task } from '../models/index.js';

const router = Router();

// Helper pour journaliser les activités
const logActivity = async (userId, action, details, req) => {
  try {
    await Activity.create({
      user: userId,
      action,
      target: 'project',
      details,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

// Helper pour recalculer la progression d'un projet
const recalculateProjectProgress = async (projectId) => {
  try {
    const tasks = await Task.find({ project: projectId });

    if (tasks.length === 0) {
      await Project.findByIdAndUpdate(projectId, { progress: 0 });
      return;
    }

    // Calculer la moyenne des progrès des tâches
    const totalProgress = tasks.reduce((sum, task) => sum + task.progress, 0);
    const avgProgress = Math.round(totalProgress / tasks.length);

    // Vérifier si toutes les tâches sont terminées
    const allCompleted = tasks.every(task => task.status === 'done');
    const status = allCompleted ? 'completed' : 'active';

    await Project.findByIdAndUpdate(projectId, { progress: avgProgress, status });
  } catch (error) {
    console.error('Failed to recalculate project progress:', error);
  }
};

// Récupérer tous les projets
router.get('/', auth, async (req, res) => {
  try {
    const { status } = req.query;
    const query = status ? { status } : {};

    const projects = await Project.find(query)
      .populate('owner', 'name email')
      .sort({ createdAt: -1 });

    res.json(projects);
  } catch (error) {
    console.error('Projects fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch projects',
      message: error.message || 'Internal server error'
    });
  }
});

// Récupérer un projet par ID
router.get('/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id)
      .populate('owner', 'name email');

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The requested project does not exist'
      });
    }

    res.json(project);
  } catch (error) {
    console.error('Project fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch project',
      message: error.message || 'Internal server error'
    });
  }
});

// Créer un nouveau projet
router.post('/', auth, admin, async (req, res) => {
  try {
    const { name, description } = req.body;

    const project = await Project.create({
      name,
      description,
      owner: req.user.id,
      status: 'active',
      progress: 0
    });

    await logActivity(req.user.id, 'project.create', `Created project: ${name}`, req);

    res.status(201).json(project);
  } catch (error) {
    console.error('Project creation error:', error);
    res.status(500).json({
      error: 'Failed to create project',
      message: error.message || 'Internal server error'
    });
  }
});

// Mettre à jour un projet
router.patch('/:id', auth, admin, async (req, res) => {
  try {
    const { name, description, status } = req.body;
    const updates = {};

    if (name) updates.name = name;
    if (description) updates.description = description;
    if (status && ['active', 'completed', 'archived'].includes(status)) {
      updates.status = status;
    }

    const project = await Project.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    );

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The requested project does not exist'
      });
    }

    await logActivity(req.user.id, 'project.update', `Updated project: ${project.name}`, req);

    res.json(project);
  } catch (error) {
    console.error('Project update error:', error);
    res.status(500).json({
      error: 'Failed to update project',
      message: error.message || 'Internal server error'
    });
  }
});

// Supprimer un projet
router.delete('/:id', auth, admin, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);

    if (!project) {
      return res.status(404).json({
        error: 'Project not found',
        message: 'The requested project does not exist'
      });
    }

    // Supprimer toutes les tâches liées
    await Task.deleteMany({ project: req.params.id });

    // Supprimer le projet
    await Project.findByIdAndDelete(req.params.id);

    await logActivity(req.user.id, 'project.delete', `Deleted project: ${project.name}`, req);

    res.status(204).end();
  } catch (error) {
    console.error('Project deletion error:', error);
    res.status(500).json({
      error: 'Failed to delete project',
      message: error.message || 'Internal server error'
    });
  }
});

export default router;
export { recalculateProjectProgress };
