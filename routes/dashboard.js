const express = require('express');
const router = express.Router();
const Project = require('../models/Project');
const Task = require('../models/Task');
const auth = require('../middleware/auth');

router.get('/stats', auth, async (req, res) => {
    try {
        // Récupérer tous les projets
        const projects = await Project.find();
        
        // Récupérer toutes les tâches
        const tasks = await Task.find()
            .sort({ createdAt: -1 })
            .limit(10);  // Limiter à 10 tâches récentes

        // Calculer les statistiques des projets
        const projectStats = {
            total: projects.length,
            inProgress: projects.filter(p => p.status === 'in_progress').length,
            completed: projects.filter(p => p.status === 'completed').length,
            notStarted: projects.filter(p => p.status === 'not_started').length,
            delayed: projects.filter(p => p.status === 'delayed').length
        };

        // Calculer les statistiques des tâches
        const taskStats = {
            total: tasks.length,
            inProgress: tasks.filter(t => t.status === 'in_progress').length,
            completed: tasks.filter(t => t.status === 'completed').length,
            notStarted: tasks.filter(t => t.status === 'not_started').length,
            priority: {
                high: tasks.filter(t => t.priority === 'high').length,
                medium: tasks.filter(t => t.priority === 'medium').length,
                low: tasks.filter(t => t.priority === 'low').length
            }
        };

        // Formater les tâches récentes
        const recentTasks = tasks.map(task => ({
            id: task._id,
            title: task.title,
            description: task.description,
            status: task.status,
            priority: task.priority,
            dueDate: task.dueDate
        }));

        res.json({
            projects: projectStats,
            tasks: taskStats,
            recentTasks
        });
    } catch (error) {
        console.error('Dashboard stats error:', error);
        res.status(500).json({ message: 'Erreur lors de la récupération des statistiques' });
    }
});

module.exports = router;
