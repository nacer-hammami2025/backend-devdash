const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

// Import controller functions
const { 
  generateReport,
  optimizeProject,
  planResources,
  analyzeRisks
} = require('../controllers/projectManagementController');

// Routes
router.post('/report', auth, generateReport);
router.post('/optimize', auth, optimizeProject);
router.post('/resources/plan', auth, planResources);
router.get('/risks/:projectId', auth, analyzeRisks);

module.exports = router;
