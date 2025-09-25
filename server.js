import bcrypt from 'bcryptjs';
import cors from 'cors';
import crypto from 'crypto';
import 'dotenv/config';
import express from 'express';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';
import morgan from 'morgan';
import OpenAI from 'openai';
import PDFDocument from 'pdfkit';
import speakeasy from 'speakeasy';

// Initialize Express app for DevDash application
const app = express();

// Middleware
app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:5173', 'http://127.0.0.1:5173', 'http://localhost:5174', 'http://127.0.0.1:5174'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Accept', 'Authorization', 'X-Session-ID', 'X-Session-Id']
  })
);
app.use(morgan('dev'));

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.error('MongoDB connection error:', err.message));

// Models
const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: false,
      default: function () {
        return this.username || (this.email ? this.email.split('@')[0] : 'User');
      }
    },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    role: { type: String, enum: ['admin', 'dev'], default: 'dev' },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorSecret: { type: String },
    tempTwoFactorSecret: { type: String },
    backupCodes: [{ code: String, used: Boolean }],
    tempBackupCodes: [{ code: String, used: Boolean }]
  },
  { timestamps: true }
);

const sessionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    token: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },
    lastActiveAt: { type: Date, default: Date.now },
    userAgent: { type: String },
    // Optional per-session preferences saved from client
    preferences: { type: mongoose.Schema.Types.Mixed, default: {} }
  },
  { timestamps: true }
);

const activitySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    action: { type: String, required: true },
    details: { type: String },
    createdAt: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

const projectSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    description: { type: String },
    // Extend status enum to match frontend (active, on_hold, completed, cancelled, archived)
    status: { type: String, enum: ['active', 'on_hold', 'completed', 'cancelled', 'archived'], default: 'active' },
    progress: { type: Number, default: 0, min: 0, max: 100 },
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    deadline: { type: Date },
    // Simple optimistic concurrency version for offline sync
    version: { type: Number, default: 0, index: true }
  },
  { timestamps: true }
);

const taskSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: { type: String },
    project: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
    assignee: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    status: { type: String, enum: ['todo', 'doing', 'review', 'done'], default: 'todo' },
    progress: { type: Number, default: 0, min: 0, max: 100 },
    version: { type: Number, default: 0, index: true }
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const Session = mongoose.model('Session', sessionSchema);
const Activity = mongoose.model('Activity', activitySchema);
const Project = mongoose.model('Project', projectSchema);
const Task = mongoose.model('Task', taskSchema);

// Auth middleware
const auth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'Authentication required', message: 'No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Set user info in request
    req.user = decoded;

    // Update session
    if (req.headers['x-session-id']) {
      try {
        await Session.findOneAndUpdate(
          { token: req.headers['x-session-id'] },
          { lastActiveAt: new Date() }
        );
      } catch (err) {
        console.error('Session update error:', err);
      }
    }

    next();
  } catch (error) {
    return res.status(401).json({ error: 'Authentication failed', message: error.message });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ error: 'Access denied', message: 'Admin privileges required' });
  }
};

// Utility to log activity
const logActivity = async (userId, action, details) => {
  try {
    await Activity.create({
      user: userId,
      action,
      details,
      createdAt: new Date()
    });
  } catch (error) {
    console.error('Activity log error:', error);
  }
};

// Auth routes
app.post('/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Registration failed', message: 'Email already in use' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // First user is admin
    const isFirstUser = (await User.countDocuments({})) === 0;

    // Create user
    const user = await User.create({
      name,
      email,
      password: hashedPassword,
      role: isFirstUser ? 'admin' : 'dev'
    });

    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const session = await Session.create({
      userId: user._id,
      token: sessionToken,
      userAgent: req.headers['user-agent']
    });

    await logActivity(user._id, 'auth.register', `User registered: ${email}`);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      session: {
        id: session._id
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed', message: error.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    // Ensure password is selected (schema has select: false)
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }

    // Check password (handle legacy users without password field)
    if (!user.password) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const session = await Session.create({
      userId: user._id,
      token: sessionToken,
      userAgent: req.headers['user-agent']
    });

    await logActivity(user._id, 'auth.login', `User logged in: ${email}`);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      session: {
        id: session._id
      }
    });
  } catch (error) {
    console.error('Login error:', error && error.stack ? error.stack : error);
    res.status(500).json({ error: 'Login failed', message: error?.message || 'Unexpected error' });
  }
});

// Sessions endpoint - FIXING 500 ERROR
app.get('/auth/sessions', auth, async (req, res) => {
  try {
    const xSessionId = req.headers['x-session-id'];
    const sessions = await Session.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(50);

    const formatted = sessions.map((session) => ({
      id: session._id,
      userId: session.userId,
      createdAt: session.createdAt,
      lastActiveAt: session.lastActiveAt,
      userAgent: session.userAgent
    }));

    const currentSession = xSessionId
      ? formatted.find(s => String(s.id) === String(xSessionId)) || null
      : (formatted[0] || null);

    res.json({
      sessions: formatted,
      currentSession
    });
  } catch (error) {
    console.error('Sessions fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch sessions', message: error.message });
  }
});

// Session validity check
app.get('/auth/sessions/check', auth, async (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId) {
      return res.status(200).json({ valid: false, reason: 'missing-session-id' });
    }
    const session = await Session.findOne({ _id: sessionId, userId: req.user.id });
    if (!session) {
      return res.status(200).json({ valid: false, reason: 'not-found' });
    }
    // Optionally update lastActiveAt
    await Session.updateOne({ _id: sessionId }, { $set: { lastActiveAt: new Date() } });
    res.json({ valid: true });
  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({ error: 'Failed to check session', message: error.message });
  }
});

// Refresh JWT token (simple re-issue)
app.post('/auth/sessions/refresh', auth, async (req, res) => {
  try {
    const token = jwt.sign(
      { id: req.user.id, role: req.user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
    res.json({ token, expiresAt });
  } catch (error) {
    console.error('Session refresh error:', error);
    res.status(500).json({ error: 'Failed to refresh session', message: error.message });
  }
});

// Revoke a specific session
app.delete('/auth/sessions/:id', auth, async (req, res) => {
  try {
    const session = await Session.findOne({ _id: req.params.id, userId: req.user.id });
    if (!session) {
      return res.status(404).json({ error: 'Not found', message: 'Session not found' });
    }
    await Session.deleteOne({ _id: session._id });
    res.json({ success: true });
  } catch (error) {
    console.error('Revoke session error:', error);
    res.status(500).json({ error: 'Failed to revoke session', message: error.message });
  }
});

// Revoke all other sessions except current
app.delete('/auth/sessions/others', auth, async (req, res) => {
  try {
    const current = req.headers['x-session-id'];
    const filter = { userId: req.user.id };
    if (current) {
      filter._id = { $ne: current };
    }
    await Session.deleteMany(filter);
    res.json({ success: true });
  } catch (error) {
    console.error('Revoke other sessions error:', error);
    res.status(500).json({ error: 'Failed to revoke other sessions', message: error.message });
  }
});

// Analytics: timeseries for tasks created, completed, review, overdue, reopened
app.get('/api/analytics/trends', auth, async (req, res) => {
  try {
    // Query params: days (default 7, max 90), projectId (optional)
    const daysParam = Math.max(1, Math.min(90, parseInt(req.query.days || '7', 10) || 7));
    const { projectId } = req.query;

    const now = new Date();
    const start = new Date(now);
    start.setDate(start.getDate() - (daysParam - 1)); // include today
    start.setHours(0, 0, 0, 0);

    const projectMatch = projectId ? { project: new mongoose.Types.ObjectId(projectId) } : {};

    const groupByDay = (match, dateField) => ([
      { $match: match },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: `$${dateField}` } },
          count: { $sum: 1 }
        }
      },
      { $project: { _id: 0, day: '$_id', count: 1 } }
    ]);

    const createdMatch = { createdAt: { $gte: start }, ...projectMatch };
    const completedMatch = { updatedAt: { $gte: start }, status: 'done', ...projectMatch };
    const reviewMatch = { updatedAt: { $gte: start }, status: 'review', ...projectMatch };

    const [createdAgg, completedAgg, reviewAgg] = await Promise.all([
      Task.aggregate(groupByDay(createdMatch, 'createdAt')),
      Task.aggregate(groupByDay(completedMatch, 'updatedAt')),
      Task.aggregate(groupByDay(reviewMatch, 'updatedAt'))
    ]);

    // Overdue: requires task.deadline (optional in schema). If present, count tasks whose deadline day is within range
    // and either not done by deadline or completed after deadline.
    let overdueAgg = [];
    try {
      const overdueMatch = {
        ...projectMatch,
        deadline: { $exists: true, $ne: null, $gte: start, $lte: now }
      };
      overdueAgg = await Task.aggregate([
        { $match: overdueMatch },
        {
          $addFields: {
            deadlineDay: { $dateToString: { format: '%Y-%m-%d', date: '$deadline' } },
            completedAfterDeadline: {
              $cond: [{ $eq: ['$status', 'done'] }, { $gt: ['$updatedAt', '$deadline'] }, false]
            },
            notDoneAtDeadline: { $ne: ['$status', 'done'] }
          }
        },
        { $match: { $or: [{ completedAfterDeadline: true }, { notDoneAtDeadline: true }] } },
        { $group: { _id: '$deadlineDay', count: { $sum: 1 } } },
        { $project: { _id: 0, day: '$_id', count: 1 } }
      ]);
    } catch (e) {
      // If the collection/schema doesn't support deadline, keep an empty series
      overdueAgg = [];
    }

    // Reopened: infer from activity details when a task moved from done to other state (best-effort via text)
    let reopenedAgg = [];
    try {
      reopenedAgg = await Activity.aggregate([
        {
          $match: {
            createdAt: { $gte: start },
            action: 'task.update',
            details: { $regex: /(réouvert|reopen|reopened|rouvert)/i }
          }
        },
        {
          $group: {
            _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            count: { $sum: 1 }
          }
        },
        { $project: { _id: 0, day: '$_id', count: 1 } }
      ]);
    } catch (e) {
      reopenedAgg = [];
    }

    // Build ordered N-day series (YYYY-MM-DD)
    const days = [];
    for (let i = 0; i < daysParam; i++) {
      const d = new Date(start);
      d.setDate(start.getDate() + i);
      const key = d.toISOString().slice(0, 10);
      days.push(key);
    }

    const toSeries = (agg) => days.map((k) => (agg.find((a) => a.day === k)?.count || 0));

    res.json({
      days,
      created: toSeries(createdAgg),
      completed: toSeries(completedAgg),
      inReview: toSeries(reviewAgg),
      overdue: toSeries(overdueAgg),
      reopened: toSeries(reopenedAgg)
    });
  } catch (error) {
    console.error('Error in /api/analytics/trends:', error);
    res.status(500).json({ message: error.message || 'Failed to compute analytics trends' });
  }
});

// Update session preferences (stored on current session)
app.put('/auth/sessions/preferences', auth, async (req, res) => {
  try {
    const sessionId = req.headers['x-session-id'];
    if (!sessionId) {
      return res.status(400).json({ error: 'Missing X-Session-ID header' });
    }
    const session = await Session.findOneAndUpdate(
      { _id: sessionId, userId: req.user.id },
      { $set: { preferences: req.body || {} } },
      { new: true }
    );
    if (!session) {
      return res.status(404).json({ error: 'Not found', message: 'Session not found' });
    }
    res.json({ success: true, preferences: session.preferences });
  } catch (error) {
    console.error('Update session preferences error:', error);
    res.status(500).json({ error: 'Failed to update session preferences', message: error.message });
  }
});

// 2FA status endpoint
app.get('/auth/2fa/status', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      enabled: !!user.twoFactorEnabled,
      methods: user.twoFactorEnabled ? ['totp'] : []
    });
  } catch (error) {
    console.error('2FA status error:', error);
    res.status(500).json({ error: '2FA status check failed', message: error.message });
  }
});

// 2FA setup endpoint
app.post('/auth/2fa/setup', auth, async (req, res) => {
  let step = 'begin';
  try {
    console.log('[2FA][setup] begin', { userId: req.user?.id });
    // Use native collection to avoid any Mongoose validation
    step = 'get-collection';
    const usersCol = mongoose.connection.collection('users');
    const objectId = new mongoose.Types.ObjectId(req.user.id);
    console.log('[2FA][setup] fetching user', { objectId: String(objectId) });
    step = 'find-user';
    const user = await usersCol.findOne(
      { _id: objectId },
      { projection: { email: 1, name: 1, twoFactorEnabled: 1, tempTwoFactorSecret: 1, tempBackupCodes: 1 } }
    );
    console.log('[2FA][setup] user fetched', { found: !!user, email: user?.email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // If 2FA already enabled, do not reinitialize (avoid confusing state)
    if (user.twoFactorEnabled) {
      return res.status(409).json({ error: '2FA already enabled', message: 'Two-factor authentication is already enabled for this account.' });
    }

    // If a temp secret already exists (setup started but not verified), re-use it
    if (!user.twoFactorEnabled && user.tempTwoFactorSecret) {
      // Rebuild otpauth URL from existing secret
      const label = encodeURIComponent(`DevDash:${user.email}`);
      const issuer = encodeURIComponent('DevDash');
      const secretBase32 = user.tempTwoFactorSecret;
      const otpAuthUrl = `otpauth://totp/${label}?secret=${secretBase32}&issuer=${issuer}&period=30&digits=6&algorithm=SHA1`;
      const backupCodes = (user.tempBackupCodes || []).map((bc) => bc.code);
      return res.json({
        otpAuthUrl,
        secret: user.tempTwoFactorSecret,
        backupCodes
      });
    }

    // Ensure name is present to avoid any validation in other code paths
    if (!user.name || user.name === '') {
      step = 'ensure-name';
      const derived = (user.email ? user.email.split('@')[0] : `user_${String(objectId).slice(-6)}`);
      await usersCol.updateOne(
        { _id: objectId },
        { $set: { name: derived } },
        { bypassDocumentValidation: true }
      );
      console.log('[2FA][setup] ensured user.name', { name: derived });
    }

    // Générer un secret
    console.log('[2FA][setup] generating secret');
    step = 'generate-secret';
    const secret = speakeasy.generateSecret({
      name: `DevDash:${user.email}`
    });
    console.log('[2FA][setup] secret generated');

    // Générer un QR code
    const otpAuthUrl = secret.otpauth_url;

    // Générer des codes de secours
    console.log('[2FA][setup] generating backup codes');
    step = 'generate-backup-codes';
    const backupCodes = Array(10).fill().map(() => ({
      code: Math.floor(100000 + Math.random() * 900000).toString(),
      used: false
    }));
    console.log('[2FA][setup] backup codes generated');

    // Mettre à jour l'utilisateur avec le secret temporaire (bypass validation)
    console.log('[2FA][setup] updating user with temp secret');
    step = 'update-temp-secret';
    await usersCol.updateOne(
      { _id: objectId },
      {
        $set: {
          tempTwoFactorSecret: secret.base32,
          tempBackupCodes: backupCodes
        }
      },
      { bypassDocumentValidation: true }
    );
    console.log('[2FA][setup] user updated successfully');

    res.json({
      otpAuthUrl,
      secret: secret.base32,
      backupCodes: backupCodes.map(bc => bc.code)
    });
  } catch (error) {
    console.error('2FA setup error at step:', step, '\n', error);
    res.status(500).json({ error: '2FA setup failed', message: error.message || `Error at step ${step}` });
  }
});

// 2FA verify endpoint
app.post('/auth/2fa/verify', auth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'Verification code required' });
    }

    // Use native collection to avoid any Mongoose validation
    const usersCol = mongoose.connection.collection('users');
    const objectId = new mongoose.Types.ObjectId(req.user.id);
    const user = await usersCol.findOne(
      { _id: objectId },
      { projection: { tempTwoFactorSecret: 1, tempBackupCodes: 1 } }
    );
    if (!user || !user.tempTwoFactorSecret) {
      return res.status(400).json({ error: 'Setup 2FA first' });
    }

    // Vérifier le code
    const verified = speakeasy.totp.verify({
      secret: user.tempTwoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1 // Permettre une tolérance d'un intervalle
    });

    if (!verified) {
      return res.status(400).json({ error: 'Invalid verification code' });
    }

    // Activer 2FA pour l'utilisateur (bypass validation)
    await usersCol.updateOne(
      { _id: objectId },
      {
        $set: {
          twoFactorEnabled: true,
          twoFactorSecret: user.tempTwoFactorSecret,
          backupCodes: user.tempBackupCodes
        },
        $unset: {
          tempTwoFactorSecret: "",
          tempBackupCodes: ""
        }
      },
      { bypassDocumentValidation: true }
    );

    await logActivity(objectId, 'security.2fa.enabled', '2FA activated');

    res.json({ success: true, message: '2FA enabled successfully' });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: '2FA verification failed', message: error.message });
  }
});

// Activity logs endpoint - FIXING 500 ERROR
app.get('/auth/audit-logs', auth, async (req, res) => {
  try {
    const logs = await Activity.find({})
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(
      logs.map((log) => ({
        id: log._id,
        user: log.user,
        action: log.action,
        details: log.details,
        createdAt: log.createdAt
      }))
    );
  } catch (error) {
    console.error('Audit logs fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch audit logs', message: error.message });
  }
});

// Audit logs export - CSV
app.get('/auth/audit-logs/export/csv', auth, async (req, res) => {
  try {
    const logs = await Activity.find({})
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(200);

    const rows = [
      ['Date', 'User', 'Email', 'Action', 'Details']
    ];

    for (const log of logs) {
      const userName = log.user?.name || '';
      const userEmail = log.user?.email || '';
      const created = new Date(log.createdAt).toISOString();
      const vals = [created, userName, userEmail, log.action || '', log.details || ''];
      // CSV escaping: wrap in quotes and escape existing quotes
      rows.push(vals.map(v => '"' + String(v).replaceAll('"', '""') + '"'));
    }

    const csv = rows.map(r => r.join(',')).join('\n');
    const filename = `audit-logs-${new Date().toISOString().slice(0, 10)}.csv`;
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(csv);
  } catch (error) {
    console.error('Audit logs CSV export error:', error);
    res.status(500).json({ error: 'Failed to export CSV', message: error.message });
  }
});

// Audit logs export - PDF
app.get('/auth/audit-logs/export/pdf', auth, async (req, res) => {
  try {
    const logs = await Activity.find({})
      .populate('user', 'name email')
      .sort({ createdAt: -1 })
      .limit(200);

    res.setHeader('Content-Type', 'application/pdf');
    const filename = `audit-logs-${new Date().toISOString().slice(0, 10)}.pdf`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    const doc = new PDFDocument({ size: 'A4', margin: 40 });
    doc.pipe(res);

    // Title
    doc.fontSize(18).text('Security Audit Logs', { align: 'center' });
    doc.moveDown(0.5);
    doc.fontSize(10).fillColor('#666').text(`Generated at: ${new Date().toLocaleString()}`, { align: 'center' });
    doc.moveDown(1);
    doc.fillColor('black');

    // Table headers
    const colX = { date: 40, user: 170, email: 300, action: 430 };
    doc.fontSize(11).text('Date', colX.date, doc.y, { continued: true })
      .text('User', colX.user, doc.y, { continued: true })
      .text('Email', colX.email, doc.y, { continued: true })
      .text('Action', colX.action);
    doc.moveTo(40, doc.y + 4).lineTo(555, doc.y + 4).strokeColor('#aaa').stroke();
    doc.moveDown(0.5);

    // Rows
    doc.fontSize(10);
    const maxRows = 40; // simple pagination per page
    let rowCount = 0;
    for (const log of logs) {
      if (rowCount >= maxRows) {
        doc.addPage();
        // Repeat headers on new page
        doc.fontSize(11).fillColor('black')
          .text('Date', colX.date, doc.y, { continued: true })
          .text('User', colX.user, doc.y, { continued: true })
          .text('Email', colX.email, doc.y, { continued: true })
          .text('Action', colX.action);
        doc.moveTo(40, doc.y + 4).lineTo(555, doc.y + 4).strokeColor('#aaa').stroke();
        doc.moveDown(0.5);
        doc.fontSize(10);
        rowCount = 0;
      }
      const date = new Date(log.createdAt).toLocaleString();
      const user = log.user?.name || '';
      const email = log.user?.email || '';
      const action = log.action || '';
      const startY = doc.y;
      doc.text(date, colX.date, startY, { width: 120 })
        .text(user, colX.user, startY, { width: 120 })
        .text(email, colX.email, startY, { width: 120 })
        .text(action, colX.action, startY, { width: 140 });
      doc.moveDown(0.4);
      if (log.details) {
        doc.fillColor('#444').fontSize(9).text(String(log.details), colX.date, doc.y, { width: 530 });
        doc.fillColor('black').fontSize(10);
        doc.moveDown(0.3);
      }
      rowCount++;
    }

    doc.end();
  } catch (error) {
    console.error('Audit logs PDF export error:', error);
    res.status(500).json({ error: 'Failed to export PDF', message: error.message });
  }
});

// Project endpoints - FIXING 500 ERROR
app.get('/projects', auth, async (req, res) => {
  try {
    const { status } = req.query;
    const query = status ? { status } : {};

    const projects = await Project.find(query)
      .sort({ createdAt: -1 })
      .populate('owner', 'name email');

    res.json(projects);
  } catch (error) {
    console.error('Projects fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch projects', message: error.message });
  }
});

app.post('/projects', auth, async (req, res) => {
  try {
    const { name, description } = req.body;

    const project = await Project.create({
      name,
      description,
      status: 'active',
      progress: 0,
      owner: req.user.id
    });

    await logActivity(req.user.id, 'project.create', `Created project: ${name}`);

    res.status(201).json(project);
  } catch (error) {
    console.error('Project creation error:', error);
    res.status(500).json({ error: 'Failed to create project', message: error.message });
  }
});

app.get('/projects/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Not found', message: 'Project not found' });
    }
    res.json(project);
  } catch (error) {
    console.error('Project fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch project', message: error.message });
  }
});

// Update project
app.put('/projects/:id', auth, async (req, res) => {
  try {
    const allowed = {};
    if (typeof req.body.name === 'string') allowed.name = req.body.name;
    if (typeof req.body.description === 'string') allowed.description = req.body.description;
    if (req.body.status) allowed.status = req.body.status;
    if (req.body.deadline) allowed.deadline = req.body.deadline;

    const project = await Project.findByIdAndUpdate(
      req.params.id,
      allowed,
      { new: true }
    );
    if (!project) {
      return res.status(404).json({ error: 'Not found', message: 'Project not found' });
    }
    await logActivity(req.user.id, 'project.update', `Updated project: ${project.name}`);
    res.json(project);
  } catch (error) {
    console.error('Project update error:', error);
    res.status(500).json({ error: 'Failed to update project', message: error.message });
  }
});

// Also support PATCH
app.patch('/projects/:id', auth, async (req, res) => {
  try {
    const updates = {};
    if (req.body.name !== undefined) updates.name = req.body.name;
    if (req.body.description !== undefined) updates.description = req.body.description;
    if (req.body.status !== undefined) updates.status = req.body.status;
    if (req.body.deadline !== undefined) updates.deadline = req.body.deadline;

    const project = await Project.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    );
    if (!project) {
      return res.status(404).json({ error: 'Not found', message: 'Project not found' });
    }
    await logActivity(req.user.id, 'project.update', `Updated project: ${project.name}`);
    res.json(project);
  } catch (error) {
    console.error('Project patch error:', error);
    res.status(500).json({ error: 'Failed to update project', message: error.message });
  }
});

// Delete project (and its tasks)
app.delete('/projects/:id', auth, async (req, res) => {
  try {
    const project = await Project.findById(req.params.id);
    if (!project) {
      return res.status(404).json({ error: 'Not found', message: 'Project not found' });
    }
    // Delete related tasks
    await Task.deleteMany({ project: project._id });
    await Project.deleteOne({ _id: project._id });
    await logActivity(req.user.id, 'project.delete', `Deleted project: ${project.name}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Project delete error:', error);
    res.status(500).json({ error: 'Failed to delete project', message: error.message });
  }
});

// Task endpoints - FIXING 500 ERROR
app.get('/tasks', auth, async (req, res) => {
  try {
    const { project, status, assignee } = req.query;
    const query = {};

    if (project) query.project = project;
    if (status) query.status = status;
    if (assignee) query.assignee = assignee;

    const tasks = await Task.find(query)
      .sort({ createdAt: -1 })
      .populate('project', 'name')
      .populate('assignee', 'name email');

    res.json(tasks);
  } catch (error) {
    console.error('Tasks fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch tasks', message: error.message });
  }
});

app.post('/tasks', auth, async (req, res) => {
  try {
    const { title, description, project, assignee } = req.body;

    const task = await Task.create({
      title,
      description,
      project,
      assignee,
      status: 'todo',
      progress: 0
    });

    await logActivity(req.user.id, 'task.create', `Created task: ${title}`);

    // Recalculate project progress
    const projectTasks = await Task.find({ project: task.project });
    if (projectTasks.length > 0) {
      const progress = Math.round(
        projectTasks.reduce((sum, t) => sum + t.progress, 0) / projectTasks.length
      );
      await Project.findByIdAndUpdate(task.project, { progress });
    }

    res.status(201).json(task);
  } catch (error) {
    console.error('Task creation error:', error);
    res.status(500).json({ error: 'Failed to create task', message: error.message });
  }
});

app.patch('/tasks/:id', auth, async (req, res) => {
  try {
    const updates = {};
    if (req.body.title) updates.title = req.body.title;
    if (req.body.description) updates.description = req.body.description;
    if (req.body.assignee) updates.assignee = req.body.assignee;

    // Status update with progress mapping
    if (req.body.status) {
      updates.status = req.body.status;
      const progressMap = {
        todo: 0,
        doing: 33,
        review: 66,
        done: 100
      };
      updates.progress = progressMap[req.body.status] || 0;
    }

    const task = await Task.findByIdAndUpdate(
      req.params.id,
      updates,
      { new: true }
    ).populate('project');

    if (!task) {
      return res.status(404).json({ error: 'Not found', message: 'Task not found' });
    }

    await logActivity(req.user.id, 'task.update', `Updated task: ${task.title}`);

    // Recalculate project progress
    const projectTasks = await Task.find({ project: task.project });
    if (projectTasks.length > 0) {
      const progress = Math.round(
        projectTasks.reduce((sum, t) => sum + t.progress, 0) / projectTasks.length
      );
      await Project.findByIdAndUpdate(task.project, { progress });
    }

    res.json(task);
  } catch (error) {
    console.error('Task update error:', error);
    res.status(500).json({ error: 'Failed to update task', message: error.message });
  }
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', message: 'API is running' });
});

// Configurer un routeur pour les routes d'API
const apiRouter = express.Router();

// Attacher toutes les routes existantes au routeur API
app._router.stack.forEach(layer => {
  if (layer.route && layer.route.path) {
    const path = layer.route.path;
    const methods = layer.route.methods;

    Object.keys(methods).forEach(method => {
      const handlers = layer.route.stack.map(stack => stack.handle);
      if (handlers.length > 0) {
        apiRouter[method](path, ...handlers);
      }
    });
  }
});

// Créer des routes spécifiques pour l'API qui redirigent vers les routes existantes

// Route de login API
app.post('/api/auth/login', async (req, res) => {
  console.log('API Login route hit', req.body);
  try {
    const { email, password } = req.body;

    // Find user with password field included
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }

    // Check password (handle legacy users without password field)
    if (!user.password) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Authentication failed', message: 'Invalid credentials' });
    }

    // Enforce 2FA for admin users
    if (user.role === 'admin' && !user.twoFactorEnabled) {
      const tempToken = jwt.sign(
        { id: user._id, role: user.role, tempAuth: true },
        process.env.JWT_SECRET,
        { expiresIn: '10m' }
      );
      return res.json({
        requires2FA: true,
        setupRequired: true,
        tempToken
      });
    }

    // Vérifier 2FA pour les utilisateurs qui l'ont activée
    if (user.twoFactorEnabled) {
      // Générer un token temporaire
      const tempToken = jwt.sign(
        { id: user._id, role: user.role, tempAuth: true },
        process.env.JWT_SECRET,
        { expiresIn: '5m' }
      );

      return res.json({
        requires2FA: true,
        tempToken
      });
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const session = await Session.create({
      userId: user._id,
      token: sessionToken,
      userAgent: req.headers['user-agent']
    });

    await logActivity(user._id, 'auth.login', `User logged in: ${email}`);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      sessionId: session._id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
  } catch (error) {
    console.error('Login error:', error && error.stack ? error.stack : error);
    res.status(500).json({ error: 'Login failed', message: error?.message || 'Unexpected error' });
  }
});

// Route de vérification 2FA
app.post('/api/auth/verify-2fa', async (req, res) => {
  try {
    const { code, tempToken } = req.body;

    // Vérifier le token temporaire
    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ error: 'Invalid token', message: 'Token is invalid or expired' });
    }

    if (!decoded.tempAuth) {
      return res.status(401).json({ error: 'Invalid token type', message: 'Not a temporary authentication token' });
    }

    // Trouver l'utilisateur
    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Vérifier le code 2FA
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!verified) {
      // Vérifier s'il s'agit d'un code de secours
      const backupCodeIdx = user.backupCodes?.findIndex(bc => !bc.used && bc.code === code);
      if (backupCodeIdx === -1 || backupCodeIdx === undefined) {
        return res.status(401).json({ error: 'Invalid code', message: 'The verification code is invalid' });
      }

      // Marquer le code de secours comme utilisé via update natif pour éviter toute validation
      try {
        await mongoose.connection.collection('users').updateOne(
          { _id: new mongoose.Types.ObjectId(user._id), 'backupCodes.code': code, 'backupCodes.used': false },
          { $set: { 'backupCodes.$.used': true } },
          { bypassDocumentValidation: true }
        );
      } catch (e) {
        console.warn('Failed to mark backup code as used via native update:', e?.message || e);
      }
    }

    // Générer un token complet
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Créer une session
    const sessionToken = crypto.randomBytes(32).toString('hex');
    const session = await Session.create({
      userId: user._id,
      token: sessionToken,
      userAgent: req.headers['user-agent']
    });

    await logActivity(user._id, 'auth.login', `User logged in with 2FA: ${user.email}`);

    res.json({
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      },
      sessionId: session._id,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString()
    });
  } catch (error) {
    console.error('2FA verification error:', error);
    res.status(500).json({ error: '2FA verification failed', message: error.message });
  }
});

// Routes API pour les autres endpoints d'authentification
app.get('/api/auth/sessions', auth, (req, res) => app._router.handle({ ...req, url: '/auth/sessions' }, res));
app.get('/api/auth/sessions/check', auth, (req, res) => app._router.handle({ ...req, url: '/auth/sessions/check' }, res));
app.post('/api/auth/sessions/refresh', auth, (req, res) => app._router.handle({ ...req, url: '/auth/sessions/refresh' }, res));
app.delete('/api/auth/sessions/:id', auth, (req, res) => app._router.handle({ ...req, url: `/auth/sessions/${req.params.id}` }, res));
app.delete('/api/auth/sessions/others', auth, (req, res) => app._router.handle({ ...req, url: '/auth/sessions/others' }, res));
app.put('/api/auth/sessions/preferences', auth, (req, res) => app._router.handle({ ...req, url: '/auth/sessions/preferences' }, res));
app.get('/api/auth/audit-logs', auth, (req, res) => app._router.handle({ ...req, url: '/auth/audit-logs' }, res));
app.get('/api/auth/audit-logs/export/csv', auth, (req, res) => app._router.handle({ ...req, url: '/auth/audit-logs/export/csv' }, res));
app.get('/api/auth/audit-logs/export/pdf', auth, (req, res) => app._router.handle({ ...req, url: '/auth/audit-logs/export/pdf' }, res));
app.get('/api/auth/2fa/status', auth, (req, res) => app._router.handle({ ...req, url: '/auth/2fa/status' }, res));
app.post('/api/auth/2fa/setup', auth, (req, res) => app._router.handle({ ...req, url: '/auth/2fa/setup' }, res));
app.post('/api/auth/2fa/verify', auth, (req, res) => app._router.handle({ ...req, url: '/auth/2fa/verify' }, res));
app.post('/api/auth/2fa/disable', auth, (req, res) => app._router.handle({ ...req, url: '/auth/2fa/disable' }, res));
app.post('/api/auth/2fa/backup-codes', auth, (req, res) => app._router.handle({ ...req, url: '/auth/2fa/backup-codes' }, res));

// Routes API pour les projets et tâches
// Support delta fetch with ?since=ISO8601 (filters by updatedAt > since)
app.get('/api/projects', auth, async (req, res, next) => {
  try {
    const { since } = req.query;
    if (!since) return app._router.handle({ ...req, url: '/projects' }, res);
    const date = new Date(since);
    if (isNaN(date.getTime())) return res.status(400).json({ error: 'invalid-since' });
    const docs = await Project.find({ updatedAt: { $gt: date } }).limit(500).lean();
    return res.json(docs);
  } catch (e) {
    next(e);
  }
});
app.post('/api/projects', auth, (req, res) => app._router.handle({ ...req, url: '/projects' }, res));
app.get('/api/projects/:id', auth, (req, res) => app._router.handle({ ...req, url: `/projects/${req.params.id}` }, res));
app.put('/api/projects/:id', auth, (req, res) => app._router.handle({ ...req, url: `/projects/${req.params.id}` }, res));
app.patch('/api/projects/:id', auth, (req, res) => app._router.handle({ ...req, url: `/projects/${req.params.id}` }, res));
app.delete('/api/projects/:id', auth, (req, res) => app._router.handle({ ...req, url: `/projects/${req.params.id}` }, res));
app.get('/api/tasks', auth, async (req, res, next) => {
  try {
    const { since, projectId } = req.query;
    if (!since) return app._router.handle({ ...req, url: '/tasks' }, res);
    const date = new Date(since);
    if (isNaN(date.getTime())) return res.status(400).json({ error: 'invalid-since' });
    const filter = { updatedAt: { $gt: date } };
    if (projectId) filter.project = projectId;
    const docs = await Task.find(filter).limit(1000).lean();
    return res.json(docs);
  } catch (e) { next(e); }
});
app.post('/api/tasks', auth, (req, res) => app._router.handle({ ...req, url: '/tasks' }, res));
app.patch('/api/tasks/:id', auth, (req, res) => app._router.handle({ ...req, url: `/tasks/${req.params.id}` }, res));

// 2FA disable endpoint
app.post('/auth/2fa/disable', auth, async (req, res) => {
  try {
    const usersCol = mongoose.connection.collection('users');
    const objectId = new mongoose.Types.ObjectId(req.user.id);
    const found = await usersCol.findOne({ _id: objectId }, { projection: { _id: 1 } });
    if (!found) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Désactiver 2FA (bypass validation)
    await usersCol.updateOne(
      { _id: objectId },
      { $set: { twoFactorEnabled: false }, $unset: { twoFactorSecret: '', backupCodes: '' } },
      { bypassDocumentValidation: true }
    );

    await logActivity(objectId, 'security.2fa.disabled', '2FA deactivated');

    res.json({ success: true, message: '2FA disabled successfully' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: '2FA disable failed', message: error.message });
  }
});

// 2FA regenerate backup codes
app.post('/auth/2fa/backup-codes', auth, async (req, res) => {
  try {
    const usersCol = mongoose.connection.collection('users');
    const objectId = new mongoose.Types.ObjectId(req.user.id);
    const user = await usersCol.findOne({ _id: objectId }, { projection: { twoFactorEnabled: 1, twoFactorSecret: 1 } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (!user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not enabled' });
    }

    const backupCodes = Array.from({ length: 10 }, () => ({
      code: crypto.randomBytes(5).toString('hex').toUpperCase(),
      used: false
    }));

    await usersCol.updateOne(
      { _id: objectId },
      { $set: { backupCodes } },
      { bypassDocumentValidation: true }
    );

    await logActivity(objectId, 'security.2fa.backup_codes_regenerated', '2FA backup codes regenerated');

    res.json({ backupCodes: backupCodes.map(bc => bc.code) });
  } catch (error) {
    console.error('2FA backup codes error:', error);
    res.status(500).json({ error: '2FA backup codes generation failed', message: error.message });
  }
});

// Create test user endpoint
app.post('/setup/create-test-user', async (req, res) => {
  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email: 'admin@devdash.com' });

    if (existingUser) {
      return res.json({
        message: 'Test user already exists',
        user: {
          email: existingUser.email,
          password: 'admin123'
        }
      });
    }

    // Créer un nouvel utilisateur
    const password = await bcrypt.hash('admin123', 10);
    const user = await User.create({
      name: 'Admin',
      email: 'admin@devdash.com',
      password,
      role: 'admin'
    });

    res.status(201).json({
      message: 'Test user created successfully',
      user: {
        email: user.email,
        password: 'admin123'
      }
    });
  } catch (error) {
    console.error('Create test user error:', error);
    res.status(500).json({ error: 'Failed to create test user', message: error.message });
  }
});

// Dev helper: backfill missing user names to avoid validation issues
app.post('/setup/backfill-user-names', async (req, res) => {
  try {
    const usersCol = mongoose.connection.collection('users');
    const missingNameCursor = usersCol.find({
      $or: [
        { name: { $exists: false } },
        { name: null },
        { name: '' }
      ]
    });

    let updated = 0;
    for await (const u of missingNameCursor) {
      const derived = u.username || (u.email ? u.email.split('@')[0] : `user_${String(u._id).slice(-6)}`);
      await usersCol.updateOne(
        { _id: u._id },
        { $set: { name: derived } },
        { bypassDocumentValidation: true }
      );
      updated++;
    }

    res.json({ updated });
  } catch (error) {
    console.error('Backfill user names error:', error);
    res.status(500).json({ error: 'Backfill failed', message: error.message });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Server error',
    message: err.message || 'An unexpected error occurred'
  });
});

const PORT = process.env.PORT || 4000;

// ---------------- Realtime SSE (Server-Sent Events) ----------------
// Lightweight in-process subscriber list. For production / clustering, an external pub/sub (Redis, NATS) would be preferable.
const sseClients = new Set(); // each entry: { id, res }
let sseClientSeq = 0;

function sseSend(res, data) {
  try {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  } catch (e) {
    // Ignore broken pipe
  }
}

function broadcastEvent(evt) {
  const payload = { ...evt, ts: Date.now() };
  for (const client of sseClients) {
    sseSend(client.res, payload);
  }
}

app.get('/api/events', (req, res) => {
  // Basic auth gate: require a valid session (reuse auth middleware if desired). We allow unauth for now if needed.
  // Could add: auth(req, res, next) wrapper; but to keep patch minimal, manual check for user if previously set by upstream middleware.
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // Ajout de headers pour améliorer la compatibilité avec les proxys
  res.setHeader('X-Accel-Buffering', 'no'); // Désactive le buffering Nginx
  res.flushHeaders?.();

  // Log client IP for debugging
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  const clientId = ++sseClientSeq;
  const client = { id: clientId, res, ip: clientIp };
  sseClients.add(client);
  sseSend(res, { type: 'hello', clientId, serverTime: Date.now() });
  console.log(`[SSE] client connected #${clientId}, IP: ${clientIp}, total=${sseClients.size}`);

  // Setup keepalive ping to maintain connection (every 30 seconds)
  const pingInterval = setInterval(() => {
    try {
      sseSend(res, { type: 'ping', ts: Date.now() });
    } catch (e) {
      clearInterval(pingInterval);
    }
  }, 30000);

  req.on('close', () => {
    clearInterval(pingInterval);
    sseClients.delete(client);
    console.log(`[SSE] client disconnected #${clientId}, total=${sseClients.size}`);
  });
});

// Offline sync batch endpoint
// Contract:
// POST /api/sync/batch
// Body: { operations: [ { entity: 'project'|'task', op: 'upsert'|'delete'|'patch', data: {...}, clientId: string, version?: number, id?: string } ] }
// - upsert: full document replacement semantics (except server fields). Create if not found.
// - patch: partial update (only provided fields) on existing doc. Fails if missing id.
// - delete: remove if exists (id required).
// Conflict if version (when provided) does not match server version.
// Response: { applied: [ { clientId, id, entity, version, deleted? } ], conflicts: [ { clientId, id, entity, reason, server, client } ], serverTime }
app.post('/api/sync/batch', auth, async (req, res) => {
  const started = Date.now();
  const { operations } = req.body || {};
  if (!Array.isArray(operations)) {
    return res.status(400).json({ error: 'invalid-body', message: 'operations array required' });
  }

  const applied = [];
  const conflicts = [];

  for (const op of operations) {
    // Basic validation
    if (!op || typeof op !== 'object') continue;
    const { entity, data, clientId, version, id, op: action } = op;
    if (!clientId) continue;
    if (!['project', 'task'].includes(entity)) {
      conflicts.push({ clientId, entity, reason: 'unsupported-entity' });
      continue;
    }
    if (!['upsert', 'delete', 'patch'].includes(action)) {
      conflicts.push({ clientId, entity, reason: 'unsupported-op' });
      continue;
    }

    try {
      if (entity === 'project') {
        if (action === 'delete') {
          if (!id) { conflicts.push({ clientId, entity, reason: 'missing-id' }); continue; }
          const existing = await Project.findById(id);
          if (!existing) { applied.push({ clientId, entity, id, version: 0, deleted: true }); continue; }
          await Project.deleteOne({ _id: id });
          applied.push({ clientId, entity, id, version: existing.version + 1, deleted: true });
          broadcastEvent({ type: 'project.deleted', id });
          continue;
        }
        if (action === 'patch') {
          if (!id) { conflicts.push({ clientId, entity, reason: 'missing-id' }); continue; }
          const existing = await Project.findById(id);
          if (!existing) { conflicts.push({ clientId, entity, id, reason: 'not-found' }); continue; }
          if (version !== undefined && version !== existing.version) {
            conflicts.push({ clientId, entity, id, reason: 'version-mismatch', server: { version: existing.version, updatedAt: existing.updatedAt }, client: { version } });
            continue;
          }
          existing.set({ ...data });
          existing.version = existing.version + 1;
          await existing.save();
          applied.push({ clientId, entity, id: existing._id, version: existing.version });
          broadcastEvent({ type: 'project.updated', id: existing._id, version: existing.version });
          continue;
        }
        // upsert (full)
        if (id) {
          const existing = await Project.findById(id);
          if (!existing) {
            // Treat as create
            const created = await Project.create({ ...data, owner: req.user.id });
            applied.push({ clientId, entity, id: created._id, version: created.version });
            broadcastEvent({ type: 'project.created', id: created._id, version: created.version });
          } else {
            if (version !== undefined && version !== existing.version) {
              conflicts.push({ clientId, entity, id, reason: 'version-mismatch', server: { version: existing.version, updatedAt: existing.updatedAt }, client: { version } });
              continue;
            }
            existing.set({ ...data });
            existing.version = existing.version + 1;
            await existing.save();
            applied.push({ clientId, entity, id: existing._id, version: existing.version });
            broadcastEvent({ type: 'project.updated', id: existing._id, version: existing.version });
          }
        } else {
          const created = await Project.create({ ...data, owner: req.user.id });
          applied.push({ clientId, entity, id: created._id, version: created.version });
          broadcastEvent({ type: 'project.created', id: created._id, version: created.version });
        }
      } else if (entity === 'task') {
        if (action === 'delete') {
          if (!id) { conflicts.push({ clientId, entity, reason: 'missing-id' }); continue; }
          const existing = await Task.findById(id);
          if (!existing) { applied.push({ clientId, entity, id, version: 0, deleted: true }); continue; }
          await Task.deleteOne({ _id: id });
          applied.push({ clientId, entity, id, version: existing.version + 1, deleted: true });
          broadcastEvent({ type: 'task.deleted', id });
          continue;
        }
        if (action === 'patch') {
          if (!id) { conflicts.push({ clientId, entity, reason: 'missing-id' }); continue; }
          const existing = await Task.findById(id);
          if (!existing) { conflicts.push({ clientId, entity, id, reason: 'not-found' }); continue; }
          if (version !== undefined && version !== existing.version) {
            conflicts.push({ clientId, entity, id, reason: 'version-mismatch', server: { version: existing.version, updatedAt: existing.updatedAt }, client: { version } });
            continue;
          }
          existing.set({ ...data });
          existing.version = existing.version + 1;
          await existing.save();
          applied.push({ clientId, entity, id: existing._id, version: existing.version });
          broadcastEvent({ type: 'task.updated', id: existing._id, version: existing.version, project: existing.project });
          continue;
        }
        if (id) {
          const existing = await Task.findById(id);
          if (!existing) {
            const created = await Task.create({ ...data });
            applied.push({ clientId, entity, id: created._id, version: created.version });
            broadcastEvent({ type: 'task.created', id: created._id, version: created.version, project: created.project });
          } else {
            if (version !== undefined && version !== existing.version) {
              conflicts.push({ clientId, entity, id, reason: 'version-mismatch', server: { version: existing.version, updatedAt: existing.updatedAt }, client: { version } });
              continue;
            }
            existing.set({ ...data });
            existing.version = existing.version + 1;
            await existing.save();
            applied.push({ clientId, entity, id: existing._id, version: existing.version });
            broadcastEvent({ type: 'task.updated', id: existing._id, version: existing.version, project: existing.project });
          }
        } else {
          const created = await Task.create({ ...data });
          applied.push({ clientId, entity, id: created._id, version: created.version });
          broadcastEvent({ type: 'task.created', id: created._id, version: created.version, project: created.project });
        }
      }
    } catch (e) {
      conflicts.push({ clientId, entity, id, reason: 'exception', message: e.message });
    }
  }

  res.json({ applied, conflicts, serverTime: new Date().toISOString(), tookMs: Date.now() - started });
});

// ---------------- AI Integration (Feature Flag Controlled) ----------------
const ENABLE_AI = process.env.ENABLE_AI === '1' || process.env.ENABLE_AI === 'true';
const STUB_AI = process.env.STUB_AI === '1' || process.env.STUB_AI === 'true';
const AI_MODEL = process.env.AI_MODEL || 'gpt-4o-mini';
const SUMMARY_TTL_MINUTES = parseInt(process.env.AI_SUMMARY_TTL_MINUTES || '15', 10);

let openaiClient = null;
if (ENABLE_AI && !STUB_AI && process.env.OPENAI_API_KEY) {
  try {
    openaiClient = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    console.log('[AI] OpenAI client initialized');
  } catch (e) {
    console.warn('[AI] Failed to init OpenAI client:', e.message);
  }
} else if (ENABLE_AI) {
  console.log('[AI] Running in stub mode or missing API key');
}

// Simple in-memory caches and rate limiting
const aiSummaryCache = new Map(); // projectId -> { summary, expiresAt }
const aiRateWindow = { count: 0, resetAt: Date.now() + 60_000 };
const AI_RATE_LIMIT = parseInt(process.env.AI_RATE_LIMIT_PER_MIN || '30', 10);

function aiRateLimitOk() {
  const now = Date.now();
  if (now > aiRateWindow.resetAt) {
    aiRateWindow.count = 0;
    aiRateWindow.resetAt = now + 60_000;
  }
  aiRateWindow.count += 1;
  return aiRateWindow.count <= AI_RATE_LIMIT;
}

async function runOpenAI(prompt, maxTokens = 300) {
  if (STUB_AI || !openaiClient) {
    return `STUB_AI_RESPONSE: ${prompt.slice(0, 80)}...`;
  }
  const completion = await openaiClient.chat.completions.create({
    model: AI_MODEL,
    messages: [
      { role: 'system', content: 'You are an assistant that produces concise JSON-friendly text.' },
      { role: 'user', content: prompt }
    ],
    max_tokens: maxTokens,
    temperature: 0.3
  });
  return completion.choices?.[0]?.message?.content?.trim() || '';
}

// Task description suggestion
app.post('/api/ai/task/suggest-description', auth, async (req, res) => {
  try {
    if (!ENABLE_AI) return res.status(503).json({ error: 'ai-disabled', message: 'AI feature disabled' });
    if (!aiRateLimitOk()) return res.status(429).json({ error: 'rate-limit', message: 'AI rate limit exceeded' });
    const { title, existingDescription, projectName } = req.body || {};
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'invalid-input', message: 'title required' });
    const prompt = `Generate a concise task description (max 120 words) for a software engineering context.\nTitle: ${title}\nProject: ${projectName || 'Unknown'}\nCurrent Description: ${existingDescription || '(none)'}\nReturn plain text only.`;
    const suggestion = await runOpenAI(prompt, 220);
    res.json({ suggestion });
  } catch (e) {
    console.error('[AI] suggest-description error', e);
    res.status(500).json({ error: 'ai-error', message: e.message });
  }
});

// Project summary
app.get('/api/ai/project/:id/summary', auth, async (req, res) => {
  try {
    if (!ENABLE_AI) return res.status(503).json({ error: 'ai-disabled', message: 'AI feature disabled' });
    if (!aiRateLimitOk()) return res.status(429).json({ error: 'rate-limit', message: 'AI rate limit exceeded' });
    const projectId = req.params.id;
    if (!projectId) return res.status(400).json({ error: 'invalid-input', message: 'project id required' });
    const cached = aiSummaryCache.get(projectId);
    const now = Date.now();
    if (cached && cached.expiresAt > now) {
      return res.json({ summary: cached.summary, cached: true, expiresAt: new Date(cached.expiresAt).toISOString() });
    }
    const project = await Project.findById(projectId);
    if (!project) return res.status(404).json({ error: 'not-found', message: 'Project not found' });
    const tasks = await Task.find({ project: projectId }).limit(200).lean();
    const stats = { total: tasks.length, byStatus: tasks.reduce((acc, t) => { acc[t.status] = (acc[t.status] || 0) + 1; return acc; }, {}) };
    const progressAvg = tasks.length ? Math.round(tasks.reduce((s, t) => s + (t.progress || 0), 0) / tasks.length) : 0;
    const prompt = `Provide an executive summary for a software project. Keep under 160 words.\nProject Name: ${project.name}\nDescription: ${project.description || '(none)'}\nOverall Progress: ${project.progress}% (tasks avg: ${progressAvg}%)\nStatus: ${project.status}\nTask Counts: ${JSON.stringify(stats.byStatus)}\nHighlight risks if: many review tasks, low progress, or overdue items (if any). Use 2 short paragraphs.`;
    const summary = await runOpenAI(prompt, 260);
    const expiresAt = now + SUMMARY_TTL_MINUTES * 60_000;
    aiSummaryCache.set(projectId, { summary, expiresAt });
    res.json({ summary, cached: false, expiresAt: new Date(expiresAt).toISOString() });
  } catch (e) {
    console.error('[AI] project summary error', e);
    res.status(500).json({ error: 'ai-error', message: e.message });
  }
});

// Subtasks suggestion endpoint
// POST /api/ai/task/suggest-subtasks { title, description, projectName, max?: number }
// Response: { subtasks: [ { title, description?, estimatedMinutes?, priority? } ] }
// Note: We validate & normalize AI output (or stub) to a stricter schema.

// Lightweight validator for AI subtasks output
function validateAndNormalizeSubtasks(rawItems, limit) {
  if (!Array.isArray(rawItems)) return [];
  const seenTitles = new Set();
  const priorities = new Set(['low', 'medium', 'high']);
  const out = [];
  for (const item of rawItems) {
    if (!item || typeof item !== 'object') continue;
    let title = (item.title || '').toString().trim();
    if (!title) continue;
    // Basic dedupe (case-insensitive)
    const key = title.toLowerCase();
    if (seenTitles.has(key)) continue;
    seenTitles.add(key);

    let description = (item.description || item.rationale || '').toString().trim();
    if (description.length > 280) description = description.slice(0, 280).trim();

    let estimated = item.estimatedMinutes;
    if (estimated == null && typeof item.estimatedHours === 'number') {
      estimated = item.estimatedHours * 60; // convert hours -> minutes
    }
    if (typeof estimated === 'string') {
      const parsed = parseFloat(estimated);
      estimated = isNaN(parsed) ? undefined : parsed;
    }
    if (typeof estimated === 'number') {
      // Clamp 5 min to 3 days (4320 minutes)
      estimated = Math.min(4320, Math.max(5, Math.round(estimated)));
    } else {
      estimated = undefined;
    }

    let priority = (item.priority || '').toString().toLowerCase();
    if (!priorities.has(priority)) priority = undefined;

    out.push({
      title: title.slice(0, 80),
      description: description || undefined,
      estimatedMinutes: estimated,
      priority
    });
    if (out.length >= limit) break;
  }
  return out;
}
app.post('/api/ai/task/suggest-subtasks', auth, async (req, res) => {
  try {
    if (!ENABLE_AI) return res.status(503).json({ error: 'ai-disabled', message: 'AI feature disabled' });
    if (!aiRateLimitOk()) return res.status(429).json({ error: 'rate-limit', message: 'AI rate limit exceeded' });
    const { title, description, projectName, max } = req.body || {};
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'invalid-input', message: 'title required' });
    const limit = Math.min(12, Math.max(2, parseInt(max || '6', 10)));
    const basePrompt = `Break down the following task into ${limit} concise actionable subtasks (software engineering context).\n` +
      `Task Title: ${title}\nProject: ${projectName || 'General'}\nDescription: ${description || '(no description)'}\n` +
      `Return ONLY valid JSON array where each item = { title: string, description?: short text (<40 words), estimatedMinutes?: integer (5-4320), priority?: one of low|medium|high }. ` +
      `Avoid duplicates, ensure logical ordering, focus on concrete deliverables.`;
    const raw = await runOpenAI(basePrompt, 420);
    let subtasks = [];
    if (STUB_AI || raw.startsWith('STUB_AI_RESPONSE')) {
      subtasks = Array.from({ length: limit }).map((_, i) => ({
        title: `Sous-tâche ${i + 1}: ${title.slice(0, 40)}`,
        description: 'Générée en mode stub pour démonstration.',
        estimatedMinutes: 30 + i * 15,
        priority: i === 0 ? 'high' : (i % 2 === 0 ? 'medium' : 'low')
      }));
    } else {
      // Attempt to parse JSON anywhere in response
      const jsonMatch = raw.match(/\[[\s\S]*\]/);
      if (jsonMatch) {
        try {
          const parsed = JSON.parse(jsonMatch[0]);
          if (Array.isArray(parsed)) subtasks = parsed;
        } catch (e) {
          console.warn('[AI] Failed to parse subtasks JSON, fallback stub');
        }
      }
      if (!Array.isArray(subtasks) || !subtasks.length) {
        subtasks = [{ title: 'Analyze requirements', description: 'Fallback stub due to parse failure', estimatedMinutes: 60 }];
      }
    }
    // Validate & normalize to final schema
    const normalized = validateAndNormalizeSubtasks(subtasks, limit);
    if (!normalized.length) {
      // Final safety fallback (should rarely happen)
      normalized.push({ title: 'Draft initial plan', description: 'Fallback generated because all AI items invalid' });
    }
    res.json({ subtasks: normalized, count: normalized.length, model: STUB_AI ? 'stub' : AI_MODEL });
  } catch (e) {
    console.error('[AI] suggest-subtasks error', e);
    res.status(500).json({ error: 'ai-error', message: e.message });
  }
});

// Task metadata suggestion endpoint (status + estimated duration)
// POST /api/ai/task/suggest-metadata { title, description?, projectName?, currentStatus?, currentEstimateMinutes? }
// Response: { suggestedStatus, estimatedMinutes, confidence, model }
// Status whitelist kept small & aligned with existing Task.status domain (assumed):
//   backlog | todo | in-progress | review | done | blocked
const TASK_STATUS_SET = new Set(['backlog', 'todo', 'in-progress', 'review', 'done', 'blocked']);

app.post('/api/ai/task/suggest-metadata', auth, async (req, res) => {
  try {
    if (!ENABLE_AI) return res.status(503).json({ error: 'ai-disabled', message: 'AI feature disabled' });
    if (!aiRateLimitOk()) return res.status(429).json({ error: 'rate-limit', message: 'AI rate limit exceeded' });
    const { title, description, projectName, currentStatus, currentEstimateMinutes } = req.body || {};
    if (!title || typeof title !== 'string') return res.status(400).json({ error: 'invalid-input', message: 'title required' });

    // Build prompt requesting strict JSON object
    const prompt = `Given a software engineering task, estimate its likely workflow status and a rough effort in minutes.\n` +
      `Return ONLY a single JSON object: { \"suggestedStatus\": one of backlog|todo|in-progress|review|done|blocked, \"estimatedMinutes\": integer 5-4320, \"confidence\": number 0-1 }.\n` +
      `Prefer not to output done unless title implies completion. Avoid blocked unless explicit blockers are described.\n` +
      `Task Title: ${title}\nProject: ${projectName || 'General'}\nDescription: ${description || '(none)'}\n` +
      `Current Status: ${currentStatus || '(unknown)'}\nCurrent Estimate: ${currentEstimateMinutes || '(none)'}\n` +
      `Consider common software task sizing heuristics (small <2h, medium <1d, large multi-day).`;

    let suggestedStatus = 'todo';
    let estimatedMinutes = 60; // default 1h
    let confidence = 0.55;

    if (STUB_AI) {
      const lower = (title + ' ' + (description || '')).toLowerCase();
      if (/(bug|fix|error|issue)/.test(lower)) suggestedStatus = 'in-progress';
      else if (/(design|spec|plan)/.test(lower)) suggestedStatus = 'backlog';
      else if (/(refactor|optimi[sz]e)/.test(lower)) suggestedStatus = 'todo';
      else if (/(deploy|release)/.test(lower)) suggestedStatus = 'review';
      // crude size heuristic: title length * factor
      estimatedMinutes = Math.min(4320, Math.max(15, Math.round(title.length * 5 + (description ? Math.min(description.length / 4, 600) : 0))));
      confidence = 0.5 + Math.min(0.4, title.length / 100);
    } else {
      const raw = await runOpenAI(prompt, 160);
      // Try to parse JSON object anywhere in response
      let obj = null;
      const jsonMatch = raw.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try { obj = JSON.parse(jsonMatch[0]); } catch (_) { /* ignore */ }
      }
      if (obj && typeof obj === 'object') {
        if (obj.suggestedStatus && TASK_STATUS_SET.has(obj.suggestedStatus)) {
          suggestedStatus = obj.suggestedStatus;
        }
        if (typeof obj.estimatedMinutes === 'number' && isFinite(obj.estimatedMinutes)) {
          estimatedMinutes = Math.min(4320, Math.max(5, Math.round(obj.estimatedMinutes)));
        }
        if (typeof obj.confidence === 'number' && obj.confidence >= 0 && obj.confidence <= 1) {
          confidence = Math.round(obj.confidence * 100) / 100;
        }
      }
    }

    // Minor normalization adjustments
    if (!TASK_STATUS_SET.has(suggestedStatus)) suggestedStatus = 'todo';
    if (currentStatus && TASK_STATUS_SET.has(currentStatus) && currentStatus === 'done' && suggestedStatus !== 'done') {
      // Don't regress a task already marked done
      suggestedStatus = 'done';
    }

    res.json({ suggestedStatus, estimatedMinutes, confidence, model: STUB_AI ? 'stub' : AI_MODEL });
  } catch (e) {
    console.error('[AI] suggest-metadata error', e);
    res.status(500).json({ error: 'ai-error', message: e.message });
  }
});

app.listen(PORT, () => {
  console.log(`API running on http://localhost:${PORT}`);
});
