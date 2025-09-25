const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  type: {
    type: String,
    enum: ['project_created', 'project_updated', 'project_completed',
      'task_created', 'task_updated', 'task_status_changed', 'task_completed',
      'comment_added', 'file_uploaded', 'member_added'],
    required: true
  },
  description: {
    type: String,
    required: true
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project'
  },
  task: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Task'
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Performance indexes
// Activity feed per project (most recent first)
activitySchema.index({ project: 1, createdAt: -1 });
// Task specific activity timeline
activitySchema.index({ task: 1, createdAt: -1 });
// User activity auditing
activitySchema.index({ user: 1, createdAt: -1 });
// Type filter for analytics (e.g., counts of task updates)
activitySchema.index({ type: 1, createdAt: -1 });

module.exports = mongoose.model('Activity', activitySchema);
