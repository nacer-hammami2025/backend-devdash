const bcrypt = require('bcryptjs');
const User = require('./models/User');
const Project = require('./models/Project');
const Task = require('./models/Task');

module.exports = async function seed() {
  // Nettoyage ciblé
  await User.deleteMany({ $or: [
    { email: 'admin@devdash.com' },
    { email: 'user@devdash.com' }
  ]});
  await Project.deleteMany({});
  await Task.deleteMany({});

  const adminPass = await bcrypt.hash('admin123', 10);
  const userPass = await bcrypt.hash('user123', 10);

  const admin = await User.create({ username: 'admin', email: 'admin@devdash.com', password: adminPass, role: 'admin' });
  const user = await User.create({ username: 'user', email: 'user@devdash.com', password: userPass, role: 'member' });

  // Projets démo avec deadlines et statuts valides pour le modèle
  const now = Date.now();
  const projects = await Project.insertMany([
    {
      name: 'Projet Démonstration',
      description: 'Projet seedé automatiquement',
      status: 'active',
      progress: 35,
      deadline: new Date(now + 7 * 24 * 60 * 60 * 1000),
      createdBy: admin._id,
      members: [admin._id, user._id],
      priority: 'high',
      tags: ['demo', 'onboarding']
    },
    {
      name: 'Site Marketing',
      description: 'Landing page et blog',
      status: 'completed',
      progress: 100,
      deadline: new Date(now - 2 * 24 * 60 * 60 * 1000),
      createdBy: admin._id,
      members: [admin._id],
      priority: 'medium',
      tags: ['web']
    },
    {
      name: 'Design System',
      description: 'Composants UI réutilisables',
      status: 'on_hold',
      progress: 10,
      deadline: new Date(now + 30 * 24 * 60 * 60 * 1000),
      createdBy: admin._id,
      members: [user._id],
      priority: 'low',
      tags: ['design']
    },
    {
      name: 'Migration Legacy',
      description: 'Migration vers nouvelle infra',
      status: 'cancelled',
      progress: 0,
      deadline: new Date(now + 14 * 24 * 60 * 60 * 1000),
      createdBy: admin._id,
      members: [admin._id, user._id],
      priority: 'high',
      tags: ['infra']
    }
  ]);

  // Tâches démo sur différents statuts/priorités
  const [p1, p2] = projects;
  await Task.insertMany([
    {
      title: 'Configurer CI/CD',
      description: 'Pipeline GitHub Actions',
      status: 'in_progress',
      project: p1._id,
      assignedTo: admin._id,
      priority: 'high',
      deadline: new Date(now + 3 * 24 * 60 * 60 * 1000),
      createdAt: new Date(now - 2 * 60 * 60 * 1000)
    },
    {
      title: 'Écrire documentation',
      description: 'Guide de démarrage',
      status: 'todo',
      project: p1._id,
      assignedTo: user._id,
      priority: 'medium',
      deadline: new Date(now + 10 * 24 * 60 * 60 * 1000),
      createdAt: new Date(now - 1 * 60 * 60 * 1000)
    },
    {
      title: 'Déploiement production',
      description: 'V1 en ligne',
      status: 'done',
      project: p2._id,
      assignedTo: admin._id,
      priority: 'low',
      createdAt: new Date(now - 24 * 60 * 60 * 1000)
    }
  ]);
};
