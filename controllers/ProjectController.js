const Project = require('../models/Project');
const Activity = require('../models/Activity');
const Task = require('../models/Task');

class ProjectController {
  // Récupérer les statistiques d'un projet
  async getProjectStats(req, res) {
    try {
      const projectId = req.params.id;
      const project = await Project.findById(projectId);
      
      if (!project) {
        return res.status(404).json({ message: 'Projet non trouvé' });
      }

      // Vérifier les permissions
      if (!project.members.includes(req.user.id) && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission refusée' });
      }

      // Récupérer les tâches du projet
      const tasks = await Task.find({ project: projectId, isArchived: false });

      // Calculer les statistiques des tâches
      const taskStats = {
        total: tasks.length,
        byStatus: tasks.reduce((acc, task) => {
          acc[task.status] = (acc[task.status] || 0) + 1;
          return acc;
        }, {}),
        byPriority: tasks.reduce((acc, task) => {
          acc[task.priority] = (acc[task.priority] || 0) + 1;
          return acc;
        }, {})
      };

      // Calculer les tâches en retard
      const now = new Date();
      const overdueTasks = tasks.filter(task => 
        task.dueDate && task.dueDate < now && task.status !== 'completed'
      ).length;

      // Récupérer les activités récentes
      const recentActivities = await Activity.find({ project: projectId })
        .populate('user', 'name email')
        .sort('-createdAt')
        .limit(10);

      res.json({
        projectInfo: {
          name: project.name,
          description: project.description,
          startDate: project.startDate,
          dueDate: project.dueDate,
          progress: project.progress,
          isCompleted: project.isCompleted,
          membersCount: project.members.length
        },
        taskStats: {
          ...taskStats,
          overdue: overdueTasks
        },
        recentActivities
      });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Récupérer tous les projets avec statistiques
  async getAll(req, res) {
    try {
      const projects = await Project.find()
        .populate('createdBy', 'name email')
        .sort({ createdAt: -1 });
      
      // Calculer les statistiques
      const stats = {
        total: projects.length,
        active: projects.filter(p => !p.isCompleted).length,
        completed: projects.filter(p => p.isCompleted).length
      };

      res.json({ projects, stats });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Créer un nouveau projet
  async create(req, res) {
    try {
      const { name, description, deadline } = req.body;
      if (!name) return res.status(400).json({ message: 'Le nom est requis' });

      const project = new Project({
        name,
        description,
        deadline,
        createdBy: req.user.id,
        members: [req.user.id]
      });

      await project.save();

      // Enregistrer l'activité
      const activity = new Activity({
        type: 'project_created',
        description: `Projet "${name}" créé`,
        user: req.user.id,
        project: project._id
      });
      await activity.save();

      res.status(201).json(project);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Mettre à jour un projet
  async update(req, res) {
    try {
      const { id } = req.params;
      const { name, description, deadline, isCompleted } = req.body;

      const project = await Project.findById(id);
      if (!project) return res.status(404).json({ message: 'Projet non trouvé' });

      // Vérifier les permissions
      if (!project.members.includes(req.user.id) && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission refusée' });
      }

      const updates = {};
      if (name) updates.name = name;
      if (description) updates.description = description;
      if (deadline) updates.deadline = deadline;
      if (typeof isCompleted === 'boolean') updates.isCompleted = isCompleted;

      const updatedProject = await Project.findByIdAndUpdate(
        id,
        { $set: updates },
        { new: true }
      ).populate('createdBy', 'name email');

      // Enregistrer l'activité
      const activity = new Activity({
        type: 'project_updated',
        description: `Projet "${project.name}" mis à jour`,
        user: req.user.id,
        project: project._id
      });
      await activity.save();

      res.json(updatedProject);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Ajouter un membre au projet
  async addMember(req, res) {
    try {
      const { id } = req.params;
      const { userId } = req.body;

      const project = await Project.findById(id);
      if (!project) {
        return res.status(404).json({ message: 'Projet non trouvé' });
      }

      // Vérifier les permissions
      if (!project.members.includes(req.user.id) && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission refusée' });
      }

      // Vérifier si l'utilisateur est déjà membre
      if (project.members.includes(userId)) {
        return res.status(400).json({ message: 'Utilisateur déjà membre du projet' });
      }

      // Ajouter le membre
      project.members.push(userId);
      await project.save();

      // Enregistrer l'activité
      const activity = new Activity({
        type: 'member_added',
        description: `Nouveau membre ajouté au projet`,
        user: req.user.id,
        project: project._id,
        details: {
          addedUserId: userId
        }
      });
      await activity.save();

      // Retourner le projet mis à jour avec les membres peuplés
      const updatedProject = await Project.findById(id)
        .populate('members', 'name email');

      res.json(updatedProject);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Supprimer un membre du projet
  async removeMember(req, res) {
    try {
      const { id, userId } = req.params;

      const project = await Project.findById(id);
      if (!project) {
        return res.status(404).json({ message: 'Projet non trouvé' });
      }

      // Vérifier les permissions
      if (!project.members.includes(req.user.id) && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission refusée' });
      }

      // Vérifier si l'utilisateur est membre
      if (!project.members.includes(userId)) {
        return res.status(400).json({ message: 'Utilisateur non membre du projet' });
      }

      // Empêcher la suppression du créateur du projet
      if (project.createdBy.toString() === userId) {
        return res.status(400).json({ message: 'Impossible de supprimer le créateur du projet' });
      }

      // Supprimer le membre
      project.members = project.members.filter(
        member => member.toString() !== userId
      );
      await project.save();

      // Enregistrer l'activité
      const activity = new Activity({
        type: 'member_removed',
        description: `Membre retiré du projet`,
        user: req.user.id,
        project: project._id,
        details: {
          removedUserId: userId
        }
      });
      await activity.save();

      // Retourner le projet mis à jour avec les membres peuplés
      const updatedProject = await Project.findById(id)
        .populate('members', 'name email');

      res.json(updatedProject);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Supprimer un projet
  async delete(req, res) {
    try {
      const { id } = req.params;
      const project = await Project.findById(id);
      
      if (!project) return res.status(404).json({ message: 'Projet non trouvé' });
      
      // Vérifier les permissions
      if (project.createdBy.toString() !== req.user.id && req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Permission refusée' });
      }

      await project.remove();

      // Enregistrer l'activité
      const activity = new Activity({
        type: 'project_deleted',
        description: `Projet "${project.name}" supprimé`,
        user: req.user.id
      });
      await activity.save();

      res.json({ message: 'Projet supprimé avec succès' });
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }

  // Ajouter un membre au projet
  async addMember(req, res) {
    try {
      const { id } = req.params;
      const { userId } = req.body;

      const project = await Project.findById(id);
      if (!project) return res.status(404).json({ message: 'Projet non trouvé' });

      if (project.members.includes(userId)) {
        return res.status(400).json({ message: 'Membre déjà dans le projet' });
      }

      project.members.push(userId);
      await project.save();

      const activity = new Activity({
        type: 'member_added',
        description: `Nouveau membre ajouté au projet "${project.name}"`,
        user: req.user.id,
        project: project._id
      });
      await activity.save();

      res.json(project);
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
  }
}

module.exports = new ProjectController();
