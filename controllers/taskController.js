const Task = require('../models/Task');
const Project = require('../models/Project');
const Activity = require('../models/Activity');
const { applyAutomationRules } = require('../utils/taskAutomation');
const { generatePDF, generateCSV } = require('../utils/exportUtils');
const { analyze } = require('../utils/analytics');

// ...existing code... (Garder tout le code jusqu'à exports.getTaskStats)

// Obtenir les statistiques et analyses avancées des tâches
exports.getTaskStats = async (req, res) => {
  try {
    const { startDate, endDate, projectId } = req.query;
    let query = { isArchived: false };
    
    // Validation et traitement des dates
    if (startDate || endDate) {
      query.createdAt = {};
      if (startDate) {
        const parsedStartDate = new Date(startDate);
        if (isNaN(parsedStartDate)) {
          return res.status(400).json({ message: 'Date de début invalide' });
        }
        query.createdAt.$gte = parsedStartDate;
      }
      if (endDate) {
        const parsedEndDate = new Date(endDate);
        if (isNaN(parsedEndDate)) {
          return res.status(400).json({ message: 'Date de fin invalide' });
        }
        query.createdAt.$lte = parsedEndDate;
      }
    }

    // Validation du projet
    if (projectId) {
      const projectExists = await Project.findById(projectId);
      if (!projectExists) {
        return res.status(404).json({ message: 'Projet non trouvé' });
      }
      query.project = projectId;
    }

    // Filtre par projets de l'utilisateur
    if (!req.user.isAdmin) {
      const userProjects = await Project.find({ 
        members: req.user._id 
      }).select('_id');
      query.project = { $in: userProjects.map(p => p._id) };
    }

    // Statistiques par statut avec tendances
    const statusStats = await Task.aggregate([
      { $match: query },
      { $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgCompletionTime: {
          $avg: {
            $cond: [
              { $eq: ['$status', 'done'] },
              {
                $dateDiff: {
                  startDate: '$createdAt',
                  endDate: '$updatedAt',
                  unit: 'hour'
                }
              },
              null
            ]
          }
        },
        tasks: { $push: {
          id: '$_id',
          title: '$title',
          createdAt: '$createdAt',
          completedAt: {
            $cond: [
              { $eq: ['$status', 'done'] },
              '$updatedAt',
              null
            ]
          }
        }}
      }},
      { $project: {
        status: '$_id',
        count: 1,
        avgCompletionTime: 1,
        trends: {
          daily: { $size: {
            $filter: {
              input: '$tasks',
              as: 'task',
              cond: {
                $gte: ['$$task.createdAt', {
                  $subtract: [new Date(), 24 * 60 * 60 * 1000]
                }]
              }
            }
          }},
          weekly: { $size: {
            $filter: {
              input: '$tasks',
              as: 'task',
              cond: {
                $gte: ['$$task.createdAt', {
                  $subtract: [new Date(), 7 * 24 * 60 * 60 * 1000]
                }]
              }
            }
          }}
        },
        _id: 0
      }}
    ]);

    // Statistiques par priorité
    const priorityStats = await Task.aggregate([
      { $match: query },
      { $group: {
        _id: '$priority',
        count: { $sum: 1 },
        avgCompletionTime: {
          $avg: {
            $cond: [
              { $eq: ['$status', 'done'] },
              {
                $dateDiff: {
                  startDate: '$createdAt',
                  endDate: '$updatedAt',
                  unit: 'hour'
                }
              },
              null
            ]
          }
        }
      }},
      { $project: {
        priority: '$_id',
        count: 1,
        avgCompletionTime: 1,
        _id: 0
      }}
    ]);

    // Tâches en retard
    const overdueTasks = await Task.find({
      ...query,
      dueDate: { $lt: new Date() },
      status: { $ne: 'done' }
    }).select('title dueDate priority').limit(10);

    // Métriques globales
    const metrics = await Task.aggregate([
      { $match: query },
      { $group: {
        _id: null,
        totalTasks: { $sum: 1 },
        completedTasks: { 
          $sum: { $cond: [{ $eq: ['$status', 'done'] }, 1, 0] }
        },
        totalEstimatedHours: { $sum: '$estimatedHours' },
        totalActualHours: { $sum: '$actualHours' }
      }},
      { $project: {
        _id: 0,
        totalTasks: 1,
        completedTasks: 1,
        completionRate: {
          $multiply: [
            { $divide: ['$completedTasks', '$totalTasks'] },
            100
          ]
        },
        totalEstimatedHours: 1,
        totalActualHours: 1,
        efficiency: {
          $cond: [
            { $gt: ['$totalActualHours', 0] },
            { $divide: ['$totalEstimatedHours', '$totalActualHours'] },
            0
          ]
        }
      }}
    ]);

    res.json({
      metrics: metrics[0] || {
        totalTasks: 0,
        completedTasks: 0,
        completionRate: 0,
        totalEstimatedHours: 0,
        totalActualHours: 0,
        efficiency: 0
      },
      byStatus: statusStats,
      byPriority: priorityStats,
      overdueTasks
    });

  } catch (error) {
    console.error('Erreur dans getTaskStats:', error);
    res.status(500).json({ 
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
};