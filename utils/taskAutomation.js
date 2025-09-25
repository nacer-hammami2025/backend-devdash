const Task = require('../models/Task');
const Project = require('../models/Project');
const Activity = require('../models/Activity');
const User = require('../models/User');
const { sendNotification } = require('../utils/notifications');

// Règles d'automatisation
const automationRules = {
  // Notifier quand une tâche approche de sa deadline
  async checkDeadlines(task) {
    if (!task.deadline) return;
    
    const now = new Date();
    const deadline = new Date(task.deadline);
    const daysRemaining = Math.ceil((deadline - now) / (1000 * 60 * 60 * 24));

    if (daysRemaining <= 3 && daysRemaining > 0) {
      await sendNotification({
        userId: task.assignedTo,
        type: 'deadline_approaching',
        title: 'Deadline Approaching',
        message: `Task "${task.title}" is due in ${daysRemaining} days`,
        data: { taskId: task._id }
      });
    }
  },

  // Mettre à jour le statut du projet en fonction des tâches
  async updateProjectStatus(task) {
    const project = await Project.findById(task.project);
    if (!project) return;

    const tasks = await Task.find({ project: project._id, isArchived: false });
    const totalTasks = tasks.length;
    const completedTasks = tasks.filter(t => t.status === 'done').length;
    
    project.progress = Math.round((completedTasks / totalTasks) * 100);
    
    if (completedTasks === totalTasks) {
      project.status = 'completed';
    } else if (completedTasks > 0) {
      project.status = 'in_progress';
    }

    await project.save();
  },

  // Assigner automatiquement des reviewers basés sur l'expertise
  async assignReviewers(task) {
    if (task.status !== 'in_review') return;

    const project = await Project.findById(task.project);
    const potentialReviewers = project.members.filter(member => 
      member.toString() !== task.assignedTo.toString()
    );

    // Sélectionner 2 reviewers aléatoires
    const selectedReviewers = potentialReviewers
      .sort(() => 0.5 - Math.random())
      .slice(0, 2);

    task.reviewers = selectedReviewers;
    await task.save();

    // Notifier les reviewers
    for (const reviewerId of selectedReviewers) {
      await sendNotification({
        userId: reviewerId,
        type: 'review_requested',
        title: 'Review Requested',
        message: `Please review task "${task.title}"`,
        data: { taskId: task._id }
      });
    }
  },

  // Créer des sous-tâches automatiques basées sur les tags
  async createSubtasks(task) {
    const subtaskTemplates = {
      'feature': [
        { title: '📝 Write Documentation', status: 'todo' },
        { title: '🧪 Write Tests', status: 'todo' },
        { title: '👀 Code Review', status: 'todo' }
      ],
      'bug': [
        { title: '🔍 Reproduce Issue', status: 'todo' },
        { title: '🧪 Write Test Case', status: 'todo' },
        { title: '✅ Verify Fix', status: 'todo' }
      ]
    };

    const taskType = task.tags.find(tag => 
      Object.keys(subtaskTemplates).includes(tag)
    );

    if (taskType && subtaskTemplates[taskType]) {
      const subtasks = subtaskTemplates[taskType].map(template => ({
        ...template,
        parent: task._id,
        project: task.project,
        assignedTo: task.assignedTo
      }));

      await Task.insertMany(subtasks);
    }
  }
};

// Middleware pour appliquer les règles d'automatisation
const applyAutomationRules = async (task) => {
  await Promise.all([
    automationRules.checkDeadlines(task),
    automationRules.updateProjectStatus(task),
    automationRules.assignReviewers(task),
    automationRules.createSubtasks(task)
  ]);
};

module.exports = {
  automationRules,
  applyAutomationRules
};
