// Utilitaires d'analyse pour les tâches

// Calcule le taux de retravail basé sur les révisions
function calculateReworkRate(tasks) {
  const tasksWithRevisions = tasks.filter(t => 
    t.revisions && t.revisions.length > 0
  ).length;
  
  return {
    rate: (tasksWithRevisions / tasks.length) * 100,
    details: {
      tasksWithRevisions,
      totalTasks: tasks.length
    }
  };
}

// Calcule la précision des estimations
function calculateEstimationAccuracy(tasks) {
  const tasksWithEstimates = tasks.filter(t => 
    t.estimatedHours && t.actualHours
  );
  
  const accuracies = tasksWithEstimates.map(t => ({
    taskId: t._id,
    accuracy: Math.min(t.estimatedHours, t.actualHours) / 
              Math.max(t.estimatedHours, t.actualHours) * 100
  }));

  return {
    average: accuracies.reduce((acc, curr) => acc + curr.accuracy, 0) / 
             accuracies.length,
    details: accuracies
  };
}

// Calcule la densité des défauts
function calculateDefectDensity(tasks) {
  const bugTasks = tasks.filter(t => 
    t.tags.includes('bug') || 
    t.title.toLowerCase().includes('bug') ||
    t.description.toLowerCase().includes('bug')
  ).length;

  return {
    density: (bugTasks / tasks.length) * 100,
    details: {
      bugCount: bugTasks,
      totalTasks: tasks.length
    }
  };
}

// Calcule la satisfaction client basée sur les commentaires
async function calculateCustomerSatisfaction(tasks) {
  const positiveKeywords = ['merci', 'super', 'génial', 'parfait', 'excellent'];
  const negativeKeywords = ['bug', 'problème', 'erreur', 'incorrect', 'mauvais'];

  const commentSentiments = tasks.flatMap(t => 
    t.comments.map(c => {
      const content = c.content.toLowerCase();
      const positiveCount = positiveKeywords.filter(k => content.includes(k)).length;
      const negativeCount = negativeKeywords.filter(k => content.includes(k)).length;
      return {
        taskId: t._id,
        sentiment: positiveCount - negativeCount
      };
    })
  );

  const averageSentiment = commentSentiments.reduce((acc, curr) => 
    acc + curr.sentiment, 0) / commentSentiments.length;

  return {
    score: ((averageSentiment + 2) / 4) * 100, // Normalisation sur 100
    details: commentSentiments
  };
}

// Calcule l'équilibre de l'équipe
function calculateTeamBalance(productivityStats) {
  const efficiencies = productivityStats.map(user => user.efficiency || 0);
  const avg = efficiencies.reduce((a, b) => a + b) / efficiencies.length;
  const variance = efficiencies.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / 
                  efficiencies.length;

  return {
    score: 100 - (Math.sqrt(variance) * 100),
    details: {
      teamSize: productivityStats.length,
      averageEfficiency: avg,
      variance
    }
  };
}

// Identifie les actions prioritaires
function identifyHighPriorityActions(data) {
  const actions = [];

  // Vérifier les goulots d'étranglement
  const bottlenecks = data.statusStats
    .filter(s => s.count > s.avgCompletionTime * 1.5)
    .map(s => ({
      status: s.status,
      taskCount: s.count,
      recommendation: `Optimiser le processus pour le statut "${s.status}"`
    }));
  actions.push(...bottlenecks);

  // Vérifier la charge de travail
  const overloadedUsers = data.productivityStats
    .filter(u => u.totalTasks > u.tasksCompleted * 2)
    .map(u => ({
      user: u.assigneeName,
      taskCount: u.totalTasks,
      recommendation: `Redistribuer la charge de travail pour ${u.assigneeName}`
    }));
  actions.push(...overloadedUsers);

  return actions;
}

// Génère des améliorations de processus
function generateProcessImprovements(data) {
  return {
    workflowOptimizations: identifyWorkflowBottlenecks(data.statusStats),
    resourceAllocation: optimizeResourceAllocation(data.productivityStats),
    qualityImprovements: suggestQualityImprovements(data.qualityMetrics)
  };
}

// Génère des recommandations pour l'équipe
function generateTeamRecommendations(data) {
  return {
    training: identifyTrainingNeeds(data),
    collaboration: suggestCollaborationImprovements(data),
    processFeedback: generateProcessFeedback(data)
  };
}

// Identifie les opportunités d'automatisation
function identifyAutomationOpportunities(data) {
  return {
    repetitiveTasks: findRepetitiveTasks(data),
    integrationPoints: identifyIntegrationPoints(data),
    workflowAutomation: suggestWorkflowAutomation(data)
  };
}

module.exports = {
  calculateReworkRate,
  calculateEstimationAccuracy,
  calculateDefectDensity,
  calculateCustomerSatisfaction,
  calculateTeamBalance,
  identifyHighPriorityActions,
  generateProcessImprovements,
  generateTeamRecommendations,
  identifyAutomationOpportunities
};
