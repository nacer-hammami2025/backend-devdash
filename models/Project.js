const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  status: {
    type: String,
    enum: ['active', 'completed', 'on_hold', 'cancelled'],
    default: 'active'
  },
  progress: {
    type: Number,
    default: 0,
    min: 0,
    max: 100
  },
  deadline: {
    type: Date,
    required: true
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  category: {
    type: String,
    enum: ['development', 'design', 'marketing', 'other'],
    default: 'development'
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high'],
    default: 'medium'
  },
  tags: [String],
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
// Owner dashboard queries
projectSchema.index({ createdBy: 1, createdAt: -1 });
// Filtering active vs archived fast
projectSchema.index({ isArchived: 1 });
// Common list filters: status + priority
projectSchema.index({ status: 1, priority: 1 });
// Text search support for name & description (optional; weights emphasize name)
try {
  projectSchema.index({ name: 'text', description: 'text' }, { weights: { name: 5, description: 1 } });
} catch (e) {
  // ignore if text index already exists in migrations
}

module.exports = mongoose.model('Project', projectSchema);
