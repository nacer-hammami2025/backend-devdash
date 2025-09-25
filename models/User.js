const mongoose = require('mongoose');

const userPreferencesSchema = new mongoose.Schema({
  theme: {
    type: String,
    enum: ['light', 'dark'],
    default: 'light'
  },
  notifications: {
    email: {
      enabled: { type: Boolean, default: true },
      frequency: {
        type: String,
        enum: ['immediate', 'daily', 'weekly'],
        default: 'immediate'
      }
    },
    push: {
      enabled: { type: Boolean, default: true },
      types: {
        taskAssigned: { type: Boolean, default: true },
        taskUpdated: { type: Boolean, default: true },
        commentAdded: { type: Boolean, default: true },
        projectInvite: { type: Boolean, default: true },
        deadlineApproaching: { type: Boolean, default: true },
        mention: { type: Boolean, default: true }
      }
    }
  },
  dashboardLayout: {
    type: Map,
    of: {
      visible: Boolean,
      position: Number
    },
    default: () => ({
      projects: { visible: true, position: 0 },
      tasks: { visible: true, position: 1 },
      activities: { visible: true, position: 2 }
    })
  }
});

const userSchema = new mongoose.Schema({
  // Optional name for compatibility with other parts of the app
  name: {
    type: String,
    required: false,
    default: function () {
      // Try fullName/username/email local-part as a fallback
      return this.fullName || this.username || (this.email ? this.email.split('@')[0] : 'User');
    }
  },
  username: {
    type: String,
    required: true,
    unique: true
  },
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true,
    select: false
  },
  twoFactorSecret: {
    type: String,
    select: false
  },
  twoFactorEnabled: {
    type: Boolean,
    default: false
  },
  // Temp fields used during 2FA setup (promoted on verification)
  tempTwoFactorSecret: {
    type: String,
    select: false
  },
  tempBackupCodes: [{
    code: String,
    used: {
      type: Boolean,
      default: false
    }
  }],
  backupCodes: [{
    code: String,
    used: {
      type: Boolean,
      default: false
    }
  }],
  fullName: {
    type: String
  },
  avatar: {
    type: String,
    default: '/avatars/default.png'
  },
  role: {
    type: String,
    enum: ['admin', 'project_manager', 'member'],
    default: 'member'
  },
  active: {
    type: Boolean,
    default: true
  },
  preferences: {
    type: userPreferencesSchema,
    default: () => ({})
  },
  skills: [{
    name: String,
    level: {
      type: String,
      enum: ['beginner', 'intermediate', 'advanced', 'expert']
    }
  }]
}, {
  timestamps: true,
  toJSON: { virtuals: true },
  toObject: { virtuals: true }
});

module.exports = mongoose.model('User', userSchema);
