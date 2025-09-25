const request = require('supertest');
const mongoose = require('mongoose');
const app = require('../index');
const User = require('../models/User');
const Project = require('../models/Project');
const Activity = require('../models/Activity');
const { generateTestToken } = require('./testUtils');

let authToken;
let testUser;
let testProject;

describe('Project Management Controller Tests', () => {
  beforeAll(async () => {
    // Créer un utilisateur de test
    testUser = await User.create({
      email: 'test@example.com',
      password: 'password123',
      name: 'Test User',
      username: 'testuser',
      role: 'user',
      preferences: {
        theme: 'light',
        notifications: {
          email: { enabled: true, frequency: 'daily' },
          push: { enabled: true, types: ['all'] }
        }
      }
    });

    // Créer un projet de test
    testProject = await Project.create({
      name: 'Test Project',
      description: 'A test project',
      owner: testUser._id,
      members: [testUser._id]
    });

    // Générer un token d'authentification
    authToken = generateTestToken(testUser);
  });

  afterAll(async () => {
    // Nettoyer les données de test
    await User.deleteMany({});
    await Project.deleteMany({});
    await Activity.deleteMany({});
    await mongoose.connection.close();
  });

  describe('Report Generation', () => {
    it('should generate a performance report', async () => {
      const response = await request(app)
        .post('/api/project-management/report')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          type: 'performance',
          options: {
            projectId: testProject._id,
            startDate: '2025-01-01',
            endDate: '2025-12-31'
          }
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('report');
      expect(response.body).toHaveProperty('message', 'Rapport généré avec succès');
    });

    it('should validate report parameters', async () => {
      const response = await request(app)
        .post('/api/project-management/report')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          type: 'invalid_type',
          options: {
            projectId: testProject._id
          }
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Project Optimization', () => {
    it('should optimize project with auto-apply', async () => {
      const response = await request(app)
        .post('/api/project-management/optimize')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          projectId: testProject._id,
          strategies: ['workload', 'schedule'],
          autoApply: true
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('recommendations');
      expect(Array.isArray(response.body.recommendations)).toBe(true);
    });

    it('should validate optimization strategies', async () => {
      const response = await request(app)
        .post('/api/project-management/optimize')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          projectId: testProject._id,
          strategies: ['invalid_strategy']
        });

      expect(response.status).toBe(400);
    });
  });

  describe('Resource Planning', () => {
    it('should generate resource plan', async () => {
      const response = await request(app)
        .post('/api/project-management/resources/plan')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          projectId: testProject._id,
          timeframe: 3 // 3 mois
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty('resourceAllocation');
      expect(response.body).toHaveProperty('workloadDistribution');
      expect(response.body).toHaveProperty('timeline');
    });
  });

  describe('Risk Analysis', () => {
    it('should analyze project risks', async () => {
      const response = await request(app)
        .get(`/api/project-management/risks/${testProject._id}`)
        .set('Authorization', `Bearer ${authToken}`);

      expect(response.status).toBe(200);
      expect(Array.isArray(response.body.risks)).toBe(true);
      expect(response.body.risks[0]).toHaveProperty('probability');
      expect(response.body.risks[0]).toHaveProperty('impact');
      expect(response.body.risks[0]).toHaveProperty('mitigation');
    });
  });

  describe('Activity Tracking', () => {
    it('should track report generation activity', async () => {
      await request(app)
        .post('/api/project-management/report')
        .set('Authorization', `Bearer ${authToken}`)
        .send({
          type: 'performance',
          options: {
            projectId: testProject._id,
            startDate: '2025-01-01',
            endDate: '2025-12-31'
          }
        });

      const activity = await Activity.findOne({
        type: 'report_generated',
        project: testProject._id
      });

      expect(activity).toBeTruthy();
      expect(activity.details.reportType).toBe('performance');
    });
  });
});
