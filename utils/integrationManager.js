const axios = require('axios');
const crypto = require('crypto');

class IntegrationManager {
  constructor() {
    this.integrations = new Map();
    this.webhookHandlers = new Map();
  }

  // Enregistrer une nouvelle intégration
  registerIntegration(name, config) {
    this.integrations.set(name, {
      ...config,
      status: 'active',
      lastSync: null,
      webhookSecret: crypto.randomBytes(32).toString('hex')
    });
  }

  // Gérer les webhooks entrants
  async handleWebhook(integration, payload, signature) {
    const handler = this.webhookHandlers.get(integration);
    if (!handler) {
      throw new Error(`No webhook handler registered for ${integration}`);
    }

    // Vérifier la signature
    if (!this.verifyWebhookSignature(integration, payload, signature)) {
      throw new Error('Invalid webhook signature');
    }

    return handler(payload);
  }

  // Vérifier la signature du webhook
  verifyWebhookSignature(integration, payload, signature) {
    const config = this.integrations.get(integration);
    if (!config) return false;

    const hmac = crypto.createHmac('sha256', config.webhookSecret);
    const calculatedSignature = hmac.update(JSON.stringify(payload)).digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(calculatedSignature)
    );
  }

  // Synchroniser avec un service externe
  async sync(integration, data) {
    const config = this.integrations.get(integration);
    if (!config) {
      throw new Error(`Integration ${integration} not found`);
    }

    try {
      const response = await axios({
        method: config.syncMethod || 'POST',
        url: config.syncEndpoint,
        headers: this.buildHeaders(config),
        data
      });

      this.integrations.set(integration, {
        ...config,
        lastSync: new Date(),
        lastSyncStatus: 'success'
      });

      return response.data;
    } catch (error) {
      this.integrations.set(integration, {
        ...config,
        lastSync: new Date(),
        lastSyncStatus: 'error',
        lastError: error.message
      });
      throw error;
    }
  }

  // Construire les en-têtes d'authentification
  buildHeaders(config) {
    const headers = {
      'Content-Type': 'application/json',
      'User-Agent': 'DevDash-Integration/1.0'
    };

    if (config.authType === 'bearer') {
      headers.Authorization = `Bearer ${config.authToken}`;
    } else if (config.authType === 'basic') {
      const auth = Buffer.from(
        `${config.username}:${config.password}`
      ).toString('base64');
      headers.Authorization = `Basic ${auth}`;
    }

    return headers;
  }

  // Enregistrer un gestionnaire de webhook
  registerWebhookHandler(integration, handler) {
    this.webhookHandlers.set(integration, handler);
  }

  // Obtenir le statut d'une intégration
  getStatus(integration) {
    return this.integrations.get(integration);
  }

  // Lister toutes les intégrations
  listIntegrations() {
    return Array.from(this.integrations.entries()).map(([name, config]) => ({
      name,
      status: config.status,
      lastSync: config.lastSync,
      lastSyncStatus: config.lastSyncStatus
    }));
  }
}

// Configuration des intégrations courantes
const setupCommonIntegrations = (manager) => {
  // GitHub
  manager.registerIntegration('github', {
    type: 'vcs',
    syncEndpoint: process.env.GITHUB_API_URL,
    authType: 'bearer',
    authToken: process.env.GITHUB_TOKEN,
    webhookEvents: ['push', 'pull_request', 'issues']
  });

  // Jira
  manager.registerIntegration('jira', {
    type: 'project',
    syncEndpoint: process.env.JIRA_API_URL,
    authType: 'basic',
    username: process.env.JIRA_USERNAME,
    password: process.env.JIRA_API_TOKEN,
    webhookEvents: ['issue_updated', 'issue_created']
  });

  // Slack
  manager.registerIntegration('slack', {
    type: 'notification',
    syncEndpoint: process.env.SLACK_WEBHOOK_URL,
    authType: 'bearer',
    authToken: process.env.SLACK_BOT_TOKEN,
    webhookEvents: ['message']
  });

  // Azure DevOps
  manager.registerIntegration('azure', {
    type: 'devops',
    syncEndpoint: process.env.AZURE_DEVOPS_URL,
    authType: 'bearer',
    authToken: process.env.AZURE_DEVOPS_TOKEN,
    webhookEvents: ['build', 'release', 'workitem']
  });
};

// Gestionnaires de webhooks spécifiques
const setupWebhookHandlers = (manager) => {
  // GitHub
  manager.registerWebhookHandler('github', async (payload) => {
    if (payload.action === 'opened' && payload.pull_request) {
      await createTaskFromPR(payload.pull_request);
    }
  });

  // Jira
  manager.registerWebhookHandler('jira', async (payload) => {
    if (payload.issue_event_type_name === 'issue_created') {
      await syncJiraIssue(payload.issue);
    }
  });

  // Slack
  manager.registerWebhookHandler('slack', async (payload) => {
    if (payload.type === 'message' && payload.channel_type === 'im') {
      await handleSlackMessage(payload);
    }
  });
};

const integrationManager = new IntegrationManager();
setupCommonIntegrations(integrationManager);
setupWebhookHandlers(integrationManager);

module.exports = integrationManager;
