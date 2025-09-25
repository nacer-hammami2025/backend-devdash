const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const templateController = require('../controllers/templateController');
const integrationController = require('../controllers/integrationController');

// Routes pour les templates
router.post('/templates', auth, templateController.createTemplate);
router.get('/templates', auth, templateController.getTemplates);
router.post('/templates/:id/use', auth, templateController.useTemplate);

// Routes pour les intégrations
router.post('/integrations/:integration/webhook', integrationController.handleWebhook);
router.post('/integrations/:integration/sync', auth, integrationController.syncIntegration);
router.put('/integrations/:integration/configure', auth, integrationController.configureIntegration);
router.get('/integrations/:integration?/status', auth, integrationController.getIntegrationStatus);

module.exports = router;
