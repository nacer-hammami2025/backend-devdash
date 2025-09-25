const mongoose = require('mongoose');

const taskTemplateSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true
  },
  category: {
    type: String,
    required: true,
    enum: ['development', 'bug', 'documentation', 'testing', 'design', 'devops']
  },
  defaultPriority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  estimatedHours: {
    type: Number,
    required: true
  },
  checklist: [{
    item: String,
    required: Boolean,
    default: false
  }],
  subtasks: [{
    title: String,
    description: String,
    estimatedHours: Number
  }],
  labels: [String],
  automationRules: {
    autoAssign: {
      enabled: Boolean,
      roleRequired: String
    },
    notifications: {
      onCreation: [String],
      onCompletion: [String]
    },
    dependencies: [{
      templateId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'TaskTemplate'
      },
      relation: {
        type: String,
        enum: ['blocks', 'blocked_by', 'relates_to']
      }
    }]
  },
  customFields: [{
    name: String,
    type: {
      type: String,
      enum: ['text', 'number', 'date', 'select', 'multiselect']
    },
    required: Boolean,
    options: [String] // Pour les champs select/multiselect
  }],
  creator: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  project: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  usage: {
    count: {
      type: Number,
      default: 0
    },
    lastUsed: Date,
    avgCompletionTime: Number
  }
}, {
  timestamps: true
});

// Méthodes du modèle
taskTemplateSchema.statics.findByCategory = function(category) {
  return this.find({ category });
};

taskTemplateSchema.statics.findPopular = function(limit = 5) {
  return this.find()
    .sort({ 'usage.count': -1 })
    .limit(limit);
};

// Méthodes d'instance
taskTemplateSchema.methods.incrementUsage = async function() {
  this.usage.count += 1;
  this.usage.lastUsed = new Date();
  await this.save();
};

taskTemplateSchema.methods.updateCompletionTime = async function(completionTime) {
  if (!this.usage.avgCompletionTime) {
    this.usage.avgCompletionTime = completionTime;
  } else {
    // Moyenne mobile pondérée
    this.usage.avgCompletionTime = 
      (this.usage.avgCompletionTime * 0.7) + (completionTime * 0.3);
  }
  await this.save();
};

module.exports = mongoose.model('TaskTemplate', taskTemplateSchema);
