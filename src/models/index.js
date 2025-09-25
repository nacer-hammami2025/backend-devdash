import mongoose from 'mongoose';

// User model with roles (admin/dev)
const userSchema = new mongoose.Schema(
  {
    // Make name optional with a safe default to avoid validation errors
    name: {
      type: String,
      required: false,
      default: function () {
        // prefer username, fallback to email local-part, otherwise generic
        // "this" refers to the document instance in mongoose default functions
        return this.username || (this.email ? this.email.split('@')[0] : 'User');
      }
    },
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'dev'], default: 'dev' }
  },
  { timestamps: true }
);

// Project management
const projectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: String,
    status: { type: String, enum: ['active', 'completed', 'archived'], default: 'active' },
    progress: { type: Number, min: 0, max: 100, default: 0 },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  { timestamps: true }
);

// Task with workflow states
const taskSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: String,
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true, index: true },
    assignee: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['todo', 'doing', 'review', 'done'], default: 'todo', index: true },
    progress: { type: Number, min: 0, max: 100, default: 0 }
  },
  { timestamps: true }
);

// Comments on tasks with file attachments support
const commentSchema = new mongoose.Schema(
  {
    task: { type: mongoose.Schema.Types.ObjectId, ref: 'Task', required: true, index: true },
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    content: { type: String, required: true },
    attachments: [{ filename: String, path: String, mimetype: String, size: Number }]
  },
  { timestamps: true }
);

// Activity logs for audit trail
const activitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true }, // auth.login, project.create, task.update, etc.
    target: { type: String }, // project, task, user, etc.
    targetId: { type: mongoose.Schema.Types.ObjectId },
    details: String,
    ip: String,
    userAgent: String
  },
  { timestamps: true }
);

// Session management
const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    token: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    lastActivity: { type: Date, default: Date.now },
    userAgent: String,
    ip: String
  },
  { timestamps: true }
);

export const User = mongoose.model('User', userSchema);
export const Project = mongoose.model('Project', projectSchema);
export const Task = mongoose.model('Task', taskSchema);
export const Comment = mongoose.model('Comment', commentSchema);
export const Activity = mongoose.model('Activity', activitySchema);
export const Session = mongoose.model('Session', sessionSchema);

// Connect to MongoDB
export async function connectDB() {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log('MongoDB connected');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
    process.exit(1);
  }
}
