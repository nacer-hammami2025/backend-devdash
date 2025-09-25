const Activity = require('../models/Activity');

// Récupérer les activités
exports.getActivities = async (req, res) => {
  try {
    const query = {};
    const limit = parseInt(req.query.limit) || 20;
    
    // Filtre par projet si spécifié
    if (req.query.projectId) {
      query.project = req.query.projectId;
    }
    
    // Filtre par tâche si spécifiée
    if (req.query.taskId) {
      query.task = req.query.taskId;
    }
    
    // Filtre par type si spécifié
    if (req.query.type) {
      query.type = req.query.type;
    }
    
    // Si l'utilisateur n'est pas admin, ne montrer que les activités des projets auxquels il participe
    if (!req.user.isAdmin) {
      const userProjects = await Project.find({ members: req.user._id }).select('_id');
      query.project = { $in: userProjects.map(p => p._id) };
    }

    const activities = await Activity.find(query)
      .populate('user', 'name email')
      .populate('project', 'name')
      .populate('task', 'title')
      .sort('-createdAt')
      .limit(limit);

    res.json(activities);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Obtenir les statistiques d'activité
exports.getActivityStats = async (req, res) => {
  try {
    const query = {};
    const timeframe = req.query.timeframe || 'week'; // 'day', 'week', 'month'
    
    // Calculer la date de début en fonction de la période
    const startDate = new Date();
    if (timeframe === 'day') {
      startDate.setDate(startDate.getDate() - 1);
    } else if (timeframe === 'week') {
      startDate.setDate(startDate.getDate() - 7);
    } else if (timeframe === 'month') {
      startDate.setMonth(startDate.getMonth() - 1);
    }

    query.createdAt = { $gte: startDate };

    // Si l'utilisateur n'est pas admin, filtrer par ses projets
    if (!req.user.isAdmin) {
      const userProjects = await Project.find({ members: req.user._id }).select('_id');
      query.project = { $in: userProjects.map(p => p._id) };
    }

    const activities = await Activity.find(query);
    
    // Grouper les activités par type
    const stats = activities.reduce((acc, activity) => {
      acc[activity.type] = (acc[activity.type] || 0) + 1;
      return acc;
    }, {});

    res.json({
      timeframe,
      totalActivities: activities.length,
      byType: stats
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
