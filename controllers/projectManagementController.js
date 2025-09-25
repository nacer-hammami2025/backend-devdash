const reportGenerator = require('../utils/reportGenerator');
const projectOptimizer = require('../utils/projectOptimizer');
const Project = require('../models/Project');
const Activity = require('../models/Activity');

// Générer un rapport
exports.generateReport = async (req, res) => {
  try {
    const { type, options } = req.body;
    const report = await reportGenerator.generateReport(type, options);

    // Enregistrer l'activité
    const activity = new Activity({
      type: 'report_generated',
      user: req.user.userId,
      project: options.projectId,
      details: {
        reportType: type,
        parameters: options
      }
    });
    await activity.save();

    res.json({
      message: 'Rapport généré avec succès',
      report
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Optimiser un projet
exports.optimizeProject = async (req, res) => {
  try {
    const { projectId, strategies } = req.body;
    const optimization = await projectOptimizer.optimizeProject(projectId, strategies);

    // Appliquer les optimisations automatiques si activées
    if (req.body.autoApply) {
      await applyOptimizations(optimization);
    }

    // Enregistrer l'activité
    const activity = new Activity({
      type: 'project_optimized',
      user: req.user._id,
      project: projectId,
      details: {
        strategies,
        recommendations: optimization.recommendations,
        autoApplied: req.body.autoApply || false
      }
    });
    await activity.save();

    res.json(optimization);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Planifier les ressources
exports.planResources = async (req, res) => {
  try {
    const { projectId, timeframe } = req.body;
    const project = await Project.findById(projectId)
      .populate('tasks')
      .populate('members');

    const resourcePlan = await projectOptimizer.optimizeResources(project);
    const workloadOptimization = await projectOptimizer.optimizeWorkload(project);

    const plan = {
      resourceAllocation: resourcePlan.currentAllocation,
      workloadDistribution: workloadOptimization.currentDistribution,
      recommendations: [
        ...resourcePlan.recommendations,
        ...workloadOptimization.recommendations
      ],
      timeline: await generateResourceTimeline(project, timeframe)
    };

    res.json(plan);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Analyser les risques
exports.analyzeRisks = async (req, res) => {
  try {
    const { projectId } = req.params;
    const project = await Project.findById(projectId)
      .populate('tasks')
      .populate('members');

    const riskAnalysis = await projectOptimizer.optimizeRisk(project);
    
    // Enrichir l'analyse avec des données historiques
    const historicalData = await getHistoricalRiskData(project);
    const enrichedAnalysis = enrichRiskAnalysis(riskAnalysis, historicalData);

    res.json(enrichedAnalysis);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// Fonctions utilitaires
async function applyOptimizations(optimization) {
  for (const rec of optimization.recommendations) {
    switch (rec.type) {
      case 'task_reassignment':
        await applyTaskReassignment(rec);
        break;
      case 'schedule_adjustment':
        await applyScheduleAdjustment(rec);
        break;
      case 'resource_allocation':
        await applyResourceAllocation(rec);
        break;
      case 'risk_mitigation':
        await applyRiskMitigation(rec);
        break;
    }
  }
}

async function generateResourceTimeline(project, timeframe) {
  const timeline = [];
  const startDate = new Date();
  const endDate = new Date(startDate);
  endDate.setMonth(startDate.getMonth() + timeframe);

  const assignments = await calculateResourceAssignments(project, startDate, endDate);
  const capacityPlan = await calculateResourceCapacity(project.members, timeframe);
  
  return {
    timeline: assignments.map(a => ({
      ...a,
      capacity: capacityPlan.find(c => c.userId === a.userId).capacity
    })),
    startDate,
    endDate
  };
}

async function getHistoricalRiskData(project) {
  // Implémenter la récupération des données historiques
}

function enrichRiskAnalysis(analysis, historicalData) {
  // Implémenter l'enrichissement de l'analyse
}

async function applyTaskReassignment(recommendation) {
  // Implémenter la réassignation de tâche
}

async function applyScheduleAdjustment(recommendation) {
  // Implémenter l'ajustement du planning
}

async function applyResourceAllocation(recommendation) {
  // Implémenter l'allocation des ressources
}

async function applyRiskMitigation(recommendation) {
  // Implémenter la mitigation des risques
}

// Les exports sont déjà faits avec les exports individuels
