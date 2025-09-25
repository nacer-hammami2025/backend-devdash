const logger = require('../utils/logger');
const mailer = require('../utils/mailer');

class ProjectService {
  async calculateProgress(projectId) {
    try {
      const tasks = await Task.find({ project: projectId });
      if (!tasks.length) return 0;

      const completedTasks = tasks.filter(t => t.status === 'done').length;
      return Math.round((completedTasks / tasks.length) * 100);
    } catch (error) {
      logger.error('Error calculating project progress:', error);
      throw error;
    }
  }

  async notifyMembers(projectId, message) {
    try {
      const project = await Project.findById(projectId)
        .populate('members', 'email name');

      // Envoyer des emails aux membres
      for (const member of project.members) {
        await mailer.sendEmail({
          to: member.email,
          subject: `[DevDash] Mise à jour du projet : ${project.name}`,
          text: message
        });
      }
    } catch (error) {
      logger.error('Error notifying project members:', error);
      throw error;
    }
  }

  async generateReport(projectId) {
    try {
      const project = await Project.findById(projectId)
        .populate('members', 'name')
        .populate('tasks');

      const tasks = project.tasks || [];
      const progress = await this.calculateProgress(projectId);
      
      return {
        projectName: project.name,
        description: project.description,
        progress: progress,
        members: project.members.map(m => m.name),
        tasksSummary: {
          total: tasks.length,
          completed: tasks.filter(t => t.status === 'done').length,
          inProgress: tasks.filter(t => t.status === 'in_progress').length,
          pending: tasks.filter(t => t.status === 'todo').length
        }
      };
    } catch (error) {
      logger.error('Error generating project report:', error);
      throw error;
    }
  }
}

module.exports = new ProjectService();
