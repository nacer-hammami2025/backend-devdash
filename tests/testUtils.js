const jwt = require('jsonwebtoken');

/**
 * Génère un token JWT pour les tests
 * @param {Object} user - L'utilisateur pour lequel générer le token
 * @returns {string} Le token JWT
 */
exports.generateTestToken = (user) => {
  return jwt.sign(
    { id: user._id, email: user.email },
    process.env.JWT_SECRET || 'test-secret',
    { expiresIn: '1h' }
  );
};

/**
 * Crée des données de test pour un projet
 * @param {Object} user - L'utilisateur propriétaire
 * @returns {Object} Les données du projet
 */
exports.createTestProjectData = (user) => {
  return {
    name: 'Test Project',
    description: 'A test project',
    owner: user._id,
    members: [user._id],
    status: 'active',
    startDate: new Date(),
    endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // +30 jours
    tasks: []
  };
};

/**
 * Crée des données de test pour une tâche
 * @param {Object} project - Le projet parent
 * @param {Object} assignee - L'utilisateur assigné
 * @returns {Object} Les données de la tâche
 */
exports.createTestTaskData = (project, assignee) => {
  return {
    title: 'Test Task',
    description: 'A test task',
    project: project._id,
    assignee: assignee._id,
    status: 'todo',
    priority: 'medium',
    startDate: new Date(),
    dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000) // +7 jours
  };
};
