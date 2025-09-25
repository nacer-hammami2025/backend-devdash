const integrationManager = require('../utils/integrationManager');
const Activity = require('../models/Activity');
const Task = require('../models/Task');
const Project = require('../models/Project');

// Gérer les webhooks entrants
exports.handleWebhook = async (req, res) => {
  try {
    const { integration } = req.params;
    const signature = req.headers['x-webhook-signature'];

    const result = await integrationManager.handleWebhook(
      integration,
      req.body,
      signature
    );

    // Enregistrer l'activité
    const activity = new Activity({
      type: 'webhook_received',
      details: {
        integration,
        event: req.headers['x-event-type'],
        status: 'success'
      }
    });
    await activity.save();

    res.json(result);
  } catch (error) {
    // Enregistrer l'erreur
    const activity = new Activity({
      type: 'webhook_received',
      details: {
        integration: req.params.integration,
        event: req.headers['x-event-type'],
        status: 'error',
        error: error.message
      }
    });
    await activity.save();

    res.status(400).json({ message: error.message });
  }
};

// Synchroniser avec un service externe
exports.syncIntegration = async (req, res) => {
  try {
    const { integration } = req.params;
    const result = await integrationManager.sync(integration, req.body);

    const activity = new Activity({
      type: 'integration_synced',
      user: req.user._id,
      details: {
        integration,
        status: 'success'
      }
    });
    await activity.save();

    res.json(result);
  } catch (error) {
    const activity = new Activity({
      type: 'integration_synced',
      user: req.user._id,
      details: {
        integration: req.params.integration,
        status: 'error',
        error: error.message
      }
    });
    await activity.save();

    res.status(500).json({ message: error.message });
  }
};

// Configurer une nouvelle intégration
exports.configureIntegration = async (req, res) => {
  try {
    const { integration } = req.params;
    const config = req.body;

    integrationManager.registerIntegration(integration, config);

    const activity = new Activity({
      type: 'integration_configured',
      user: req.user._id,
      details: {
        integration,
        config: {
          ...config,
          authToken: '***',
          password: '***'
        }
      }
    });
    await activity.save();

    res.json({ 
      message: 'Integration configured successfully',
      status: integrationManager.getStatus(integration)
    });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};

// Obtenir le statut des intégrations
exports.getIntegrationStatus = async (req, res) => {
  try {
    const { integration } = req.params;
    const status = integration ? 
      integrationManager.getStatus(integration) :
      integrationManager.listIntegrations();

    res.json(status);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Créer une tâche à partir d'une PR GitHub
async function createTaskFromPR(pullRequest) {
  const task = new Task({
    title: `Review PR: ${pullRequest.title}`,
    description: pullRequest.body,
    status: 'in_review',
    priority: 'medium',
    source: {
      type: 'github',
      id: pullRequest.number,
      url: pullRequest.html_url
    },
    metadata: {
      branch: pullRequest.head.ref,
      commits: pullRequest.commits,
      changedFiles: pullRequest.changed_files
    }
  });

  await task.save();
  return task;
}

// Synchroniser une issue Jira
async function syncJiraIssue(issue) {
  const task = new Task({
    title: issue.fields.summary,
    description: issue.fields.description,
    status: mapJiraStatus(issue.fields.status.name),
    priority: mapJiraPriority(issue.fields.priority.name),
    source: {
      type: 'jira',
      id: issue.key,
      url: issue.self
    }
  });

  await task.save();
  return task;
}

// Gérer un message Slack
async function handleSlackMessage(message) {
  if (message.text.startsWith('/task')) {
    const task = new Task({
      title: message.text.substring(6),
      description: 'Task created from Slack',
      status: 'todo',
      source: {
        type: 'slack',
        id: message.ts,
        channel: message.channel
      }
    });

    await task.save();
    return task;
  }
}

// Fonctions utilitaires de mapping
function mapJiraStatus(status) {
  const statusMap = {
    'To Do': 'todo',
    'In Progress': 'in_progress',
    'Code Review': 'in_review',
    'Done': 'done'
  };
  return statusMap[status] || 'todo';
}

function mapJiraPriority(priority) {
  const priorityMap = {
    'Highest': 'high',
    'High': 'high',
    'Medium': 'medium',
    'Low': 'low',
    'Lowest': 'low'
  };
  return priorityMap[priority] || 'medium';
}

module.exports = {
  handleWebhook,
  syncIntegration,
  configureIntegration,
  getIntegrationStatus
};
