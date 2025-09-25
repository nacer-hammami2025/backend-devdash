const TaskTemplate = require('../models/TaskTemplate');
const Activity = require('../models/Activity');
const { applyAutomationRules } = require('../utils/taskAutomation');

// Créer un nouveau template
exports.createTemplate = async (req, res) => {
  try {
    const template = new TaskTemplate({
      ...req.body,
      creator: req.user._id
    });

    await template.save();

    const activity = new Activity({
      type: 'template_created',
      user: req.user._id,
      project: template.project,
      details: {
        templateId: template._id,
        templateName: template.name,
        category: template.category
      }
    });
    await activity.save();

    res.status(201).json(template);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Récupérer tous les templates
exports.getTemplates = async (req, res) => {
  try {
    const { category, project, sort = 'usage' } = req.query;
    const query = {};

    if (category) query.category = category;
    if (project) query.project = project;

    let sortOption = {};
    switch (sort) {
      case 'usage':
        sortOption = { 'usage.count': -1 };
        break;
      case 'recent':
        sortOption = { 'usage.lastUsed': -1 };
        break;
      case 'name':
        sortOption = { name: 1 };
        break;
      default:
        sortOption = { 'usage.count': -1 };
    }

    const templates = await TaskTemplate.find(query)
      .sort(sortOption)
      .populate('creator', 'name email')
      .populate('project', 'name');

    // Enrichir avec des statistiques d'utilisation
    const enrichedTemplates = await Promise.all(templates.map(async (template) => {
      const stats = await getTemplateStats(template._id);
      return {
        ...template.toObject(),
        stats
      };
    }));

    res.json(enrichedTemplates);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Utiliser un template pour créer une tâche
exports.useTemplate = async (req, res) => {
  try {
    const template = await TaskTemplate.findById(req.params.id);
    if (!template) {
      return res.status(404).json({ message: 'Template non trouvé' });
    }

    // Fusionner les données du template avec les données de la requête
    const taskData = {
      ...template.toObject(),
      ...req.body,
      template: template._id
    };

    // Supprimer les champs spécifiques au template
    delete taskData._id;
    delete taskData.usage;
    delete taskData.creator;
    delete taskData.createdAt;
    delete taskData.updatedAt;

    // Créer la tâche
    const task = new Task(taskData);
    await task.save();

    // Mettre à jour les statistiques d'utilisation du template
    await template.incrementUsage();

    // Appliquer les règles d'automatisation
    if (template.automationRules) {
      await applyTemplateAutomation(task, template.automationRules);
    }

    const activity = new Activity({
      type: 'template_used',
      user: req.user._id,
      project: task.project,
      task: task._id,
      details: {
        templateId: template._id,
        templateName: template.name
      }
    });
    await activity.save();

    res.status(201).json(task);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Analyser l'efficacité du template
async function getTemplateStats(templateId) {
  const tasks = await Task.find({ template: templateId });
  
  return {
    totalUsage: tasks.length,
    completionRate: calculateCompletionRate(tasks),
    avgCompletionTime: calculateAvgCompletionTime(tasks),
    successRate: calculateSuccessRate(tasks),
    commonModifications: identifyCommonModifications(tasks)
  };
}

// Fonctions utilitaires pour les statistiques
function calculateCompletionRate(tasks) {
  const completed = tasks.filter(t => t.status === 'done').length;
  return (completed / tasks.length) * 100;
}

function calculateAvgCompletionTime(tasks) {
  const completedTasks = tasks.filter(t => t.status === 'done');
  if (completedTasks.length === 0) return 0;

  const times = completedTasks.map(t => 
    t.completedAt - t.createdAt
  );
  return times.reduce((a, b) => a + b) / times.length;
}

function calculateSuccessRate(tasks) {
  const successfulTasks = tasks.filter(t => 
    !t.tags.includes('bug') && 
    !t.tags.includes('rework') &&
    t.status === 'done'
  );
  return (successfulTasks.length / tasks.length) * 100;
}

function identifyCommonModifications(tasks) {
  const modifications = tasks.reduce((acc, task) => {
    const diffs = compareWithTemplate(task);
    diffs.forEach(diff => {
      acc[diff.field] = (acc[diff.field] || 0) + 1;
    });
    return acc;
  }, {});

  return Object.entries(modifications)
    .sort(([, a], [, b]) => b - a)
    .map(([field, count]) => ({
      field,
      count,
      percentage: (count / tasks.length) * 100
    }));
}

module.exports = {
  createTemplate,
  getTemplates,
  useTemplate
};
