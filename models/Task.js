const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  attachments: [{
    filename: String,
    path: String,
    mimetype: String,
    size: Number
  }]
}, {
  timestamps: true
});

const taskSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  status: {
    type: String,
    enum: ['todo', 'in_progress', 'in_review', 'done'],
    default: 'todo'
  },
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  assignedTo: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  deadline: {
    type: Date
  },
  progress: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  tags: [String],
  comments: [commentSchema],
  watchers: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  estimatedHours: Number,
  actualHours: Number,
  isArchived: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

// Performance indexes
// Frequently queried by project when listing tasks in a board or backlog
taskSchema.index({ project: 1 });
// Common filter combination when viewing tasks assigned to a user by status
taskSchema.index({ assignedTo: 1, status: 1 });
// Sorting tasks within a project by status then recent creation
taskSchema.index({ project: 1, status: 1, createdAt: -1 });
// Quickly filter out archived tasks inside a project (partial index keeps it small)
taskSchema.index({ project: 1, isArchived: 1 }, { partialFilterExpression: { isArchived: true } });

module.exports = mongoose.model('Task', taskSchema);
