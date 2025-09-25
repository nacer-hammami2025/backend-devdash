// Simulation des fonctions d'apprentissage automatique pour les tests
exports.machineLearn = {
  // Prédire la charge de travail optimale
  predictWorkload: (historical, current) => {
    return {
      recommendations: [
        {
          type: 'workload_adjustment',
          description: 'Réduire la charge de travail de 20%',
          confidence: 0.85
        }
      ]
    };
  },

  // Prédire le planning optimal
  predictSchedule: (tasks, constraints) => {
    return {
      recommendations: [
        {
          type: 'schedule_adjustment',
          description: 'Réorganiser les tâches pour optimiser le temps',
          adjustments: [
            { taskId: '1', newStartDate: new Date() }
          ]
        }
      ]
    };
  },

  // Prédire l'allocation optimale des ressources
  predictResources: (team, tasks) => {
    return {
      recommendations: [
        {
          type: 'resource_allocation',
          description: 'Réaffecter les ressources pour une meilleure efficacité',
          allocations: [
            { memberId: '1', taskId: '2' }
          ]
        }
      ]
    };
  },

  // Prédire les risques potentiels
  predictRisks: (project) => {
    return {
      risks: [
        {
          description: 'Risque de retard dû à la complexité technique',
          probability: 0.7,
          impact: 0.8,
          mitigation: 'Ajouter des ressources techniques supplémentaires'
        }
      ]
    };
  }
};
