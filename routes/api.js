const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const projectController = require('../controllers/ProjectController');
const taskController = require('../controllers/taskController');
const activityController = require('../controllers/activityController');
const analyticsController = require('../controllers/analyticsController');
const upload = require('../middleware/upload');

// Routes des projets
router.post('/projects', auth, projectController.createProject);
router.get('/projects', auth, projectController.getProjects);
router.get('/projects/:id', auth, projectController.getProject);
router.put('/projects/:id', auth, projectController.updateProject);
router.delete('/projects/:id', auth, projectController.deleteProject);
router.post('/projects/:id/members', auth, projectController.addMember);
router.delete('/projects/:id/members/:userId', auth, projectController.removeMember);
router.get('/projects/:id/stats', auth, projectController.getProjectStats);

// Routes des tâches
router.post('/tasks', auth, taskController.createTask);
router.get('/tasks', auth, taskController.getTasks);
router.get('/tasks/stats', auth, taskController.getTaskStats);
router.get('/tasks/:id', auth, taskController.getTask);
router.put('/tasks/:id', auth, taskController.updateTask);
router.delete('/tasks/:id', auth, taskController.deleteTask);
router.post('/tasks/:id/comments', auth, upload.array('files', 5), taskController.addComment);
router.delete('/tasks/:id/comments/:commentId', auth, taskController.deleteComment);

// Routes des activités
router.get('/activities', auth, activityController.getActivities);
router.get('/activities/stats', auth, activityController.getActivityStats);

// Analytics
router.get('/analytics/trends', auth, analyticsController.getTrends);

// Routes des notifications
router.get('/notifications', auth, notificationController.getNotifications);
router.put('/notifications/:id/read', auth, notificationController.markAsRead);
router.put('/notifications/read-all', auth, notificationController.markAllAsRead);
router.delete('/notifications/:id', auth, notificationController.deleteNotification);

// Routes des utilisateurs
router.get('/profile', auth, userController.getProfile);
router.put('/profile', auth, userController.updateProfile);
router.put('/profile/preferences', auth, userController.updatePreferences);
router.put('/profile/avatar', auth, upload.single('avatar'), userController.updateAvatar);
router.put('/users/:userId/role', auth, userController.updateUserRole);

module.exports = router;
