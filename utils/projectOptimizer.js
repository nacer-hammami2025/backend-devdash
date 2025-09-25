const Task = require('../models/Task');
const Project = require('../models/Project');
const User = require('../models/User');
const { machineLearn } = require('./mlUtils');

class ProjectOptimizer {
  constructor() {
    this.optimizationStrategies = new Map([
      ['workload', this.optimizeWorkload.bind(this)],
      ['schedule', this.optimizeSchedule.bind(this)],
      ['resources', this.optimizeResources.bind(this)],
      ['risk', this.optimizeRisk.bind(this)]
    ]);
  }

  async optimize(projectId, strategies = ['workload', 'schedule', 'resources', 'risk']) {
    const project = await Project.findById(projectId)
      .populate('tasks')
      .populate('members');

    const optimizations = [];
    for (const strategy of strategies) {
      const optimizer = this.optimizationStrategies.get(strategy);
      if (optimizer) {
        const result = await optimizer.call(this, project);
        optimizations.push({ strategy, ...result });
      }
    }

    return {
      projectId,
      optimizations,
      recommendations: this.generateRecommendations(optimizations)
    };
  }

  async optimizeWorkload(project) {
    const taskAssignments = await this.analyzeTaskAssignments(project);
    const workloadDistribution = this.calculateWorkloadDistribution(project.members);
    const bottlenecks = this.identifyBottlenecks(taskAssignments);

    const recommendations = [];

    // Rééquilibrage de la charge de travail
    if (bottlenecks.length > 0) {
      const rebalancing = await this.rebalanceWorkload(project, bottlenecks);
      recommendations.push(...rebalancing);
    }

    // Identification des ressources sous-utilisées
    const underutilized = this.findUnderutilizedResources(workloadDistribution);
    if (underutilized.length > 0) {
      recommendations.push({
        type: 'resource_optimization',
        description: 'Ressources sous-utilisées détectées',
        actions: underutilized.map(resource => ({
          user: resource.userId,
          action: 'increase_allocation',
          potentialTasks: resource.suggestedTasks
        }))
      });
    }

    return {
      currentDistribution: workloadDistribution,
      bottlenecks,
      recommendations
    };
  }

  async optimizeSchedule(project) {
    const schedule = await this.analyzeProjectSchedule(project);
    const criticalPath = this.calculateCriticalPath(schedule);
    const dependencies = this.analyzeDependencies(project.tasks);

    const recommendations = [];

    // Optimisation du chemin critique
    const criticalPathOptimizations = this.optimizeCriticalPath(criticalPath);
    if (criticalPathOptimizations.length > 0) {
      recommendations.push({
        type: 'critical_path_optimization',
        optimizations: criticalPathOptimizations
      });
    }

    // Parallélisation des tâches
    const parallelizationOpportunities = this.findParallelizationOpportunities(dependencies);
    if (parallelizationOpportunities.length > 0) {
      recommendations.push({
        type: 'task_parallelization',
        opportunities: parallelizationOpportunities
      });
    }

    return {
      schedule,
      criticalPath,
      recommendations
    };
  }

  async optimizeResources(project) {
    const resourceAllocation = await this.analyzeResourceAllocation(project);
    const skillMatrix = await this.generateSkillMatrix(project.members);
    const resourceUtilization = this.calculateResourceUtilization(project);

    const recommendations = [];

    // Optimisation basée sur les compétences
    const skillBasedAssignments = this.optimizeSkillBasedAssignments(
      project.tasks,
      skillMatrix
    );
    if (skillBasedAssignments.changes.length > 0) {
      recommendations.push({
        type: 'skill_based_optimization',
        assignments: skillBasedAssignments
      });
    }

    // Identification des besoins en formation
    const trainingNeeds = this.identifyTrainingNeeds(skillMatrix, resourceUtilization);
    if (trainingNeeds.length > 0) {
      recommendations.push({
        type: 'training_needs',
        needs: trainingNeeds
      });
    }

    return {
      currentAllocation: resourceAllocation,
      skillGaps: this.identifySkillGaps(skillMatrix),
      recommendations
    };
  }

  async optimizeRisk(project) {
    const risks = await this.analyzeProjectRisks(project);
    const mitigationStrategies = this.generateMitigationStrategies(risks);
    const contingencyPlans = this.createContingencyPlans(risks);

    const recommendations = [];

    // Stratégies de mitigation des risques
    if (mitigationStrategies.length > 0) {
      recommendations.push({
        type: 'risk_mitigation',
        strategies: mitigationStrategies
      });
    }

    // Plans de contingence
    if (contingencyPlans.length > 0) {
      recommendations.push({
        type: 'contingency_plans',
        plans: contingencyPlans
      });
    }

    return {
      riskAssessment: risks,
      mitigationStrategies,
      contingencyPlans,
      recommendations
    };
  }

  async analyzeTaskAssignments(project) {
    return project.tasks.map(task => ({
      taskId: task._id,
      assignee: task.assignedTo,
      estimatedHours: task.estimatedHours,
      priority: task.priority,
      status: task.status
    }));
  }

  calculateWorkloadDistribution(members) {
    return members.map(member => ({
      userId: member._id,
      totalHours: this.calculateTotalHours(member),
      taskCount: this.calculateTaskCount(member),
      utilization: this.calculateUtilization(member)
    }));
  }

  async generateSkillMatrix(members) {
    const skills = await this.identifyRequiredSkills();
    return members.map(member => ({
      userId: member._id,
      skills: skills.map(skill => ({
        name: skill,
        level: this.assessSkillLevel(member, skill)
      }))
    }));
  }

  async rebalanceWorkload(project, bottlenecks) {
    const recommendations = [];
    for (const bottleneck of bottlenecks) {
      const alternativeAssignees = await this.findSuitableAssignees(
        bottleneck.task,
        project.members
      );
      if (alternativeAssignees.length > 0) {
        recommendations.push({
          type: 'task_reassignment',
          taskId: bottleneck.task._id,
          currentAssignee: bottleneck.task.assignedTo,
          suggestedAssignees: alternativeAssignees,
          reason: 'workload_balancing'
        });
      }
    }
    return recommendations;
  }

  generateRecommendations(optimizations) {
    return optimizations.flatMap(opt => {
      switch (opt.strategy) {
        case 'workload':
          return this.generateWorkloadRecommendations(opt);
        case 'schedule':
          return this.generateScheduleRecommendations(opt);
        case 'resources':
          return this.generateResourceRecommendations(opt);
        case 'risk':
          return this.generateRiskRecommendations(opt);
        default:
          return [];
      }
    });
  }
}

module.exports = new ProjectOptimizer();
