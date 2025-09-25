const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const User = require('../models/User');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const auth = require('../middleware/auth');
// Validation + standardized responses
const { validate } = require('../middleware/validate.js');
const { success } = require('../utils/apiResponse.js');
const { badRequest, unauthorized, notFound } = require('../utils/errors.js');
// Schemas (ESM export interop)
const { AuthRegisterSchema, AuthLoginSchema } = require('../docs/openapi.js');
// In-memory login attempts (simple, replace with Redis in production)
const loginAttempts = new Map(); // key: email, value: { count, last, lockedUntil }

function registerFailedAttempt(email) {
  if (!email) return;
  const now = Date.now();
  const entry = loginAttempts.get(email) || { count: 0, last: 0, lockedUntil: 0 };
  if (now < entry.lockedUntil) {
    // Still locked, increment silently
    entry.count += 1;
    entry.last = now;
    loginAttempts.set(email, entry);
    return entry;
  }
  if (now - entry.last > 10 * 60 * 1000) {
    // Reset window after 10 min idle
    entry.count = 0;
  }
  entry.count += 1;
  entry.last = now;
  if (entry.count >= 5) {
    // Lock for 5 minutes
    entry.lockedUntil = now + 5 * 60 * 1000;
  }
  loginAttempts.set(email, entry);
  return entry;
}

function getAttemptState(email) {
  if (!email) return { remaining: 5, locked: false, lockedUntil: 0 };
  const entry = loginAttempts.get(email);
  if (!entry) return { remaining: 5, locked: false, lockedUntil: 0 };
  const now = Date.now();
  const locked = now < entry.lockedUntil;
  return { remaining: locked ? 0 : Math.max(0, 5 - entry.count), locked, lockedUntil: entry.lockedUntil };
}

// @route   POST /api/auth/register
// @desc    Register a user
// @access  Public
router.post('/register', validate({ body: AuthRegisterSchema }), async (req, res, next) => {
  try {
    const { username, email, password } = req.validatedBody;
    let user = await User.findOne({ $or: [{ email }, { username }] });
    if (user) return next(badRequest('User already exists'));

    user = new User({
      username,
      email,
      password,
      role: 'member',
      preferences: {
        theme: 'light',
        notifications: {
          email: { enabled: true, frequency: 'immediate' },
          push: { enabled: true, types: { taskAssigned: true, taskUpdated: true, commentAdded: true, projectInvite: true, deadlineApproaching: true, mention: true } }
        },
        dashboardLayout: { projects: { visible: true, position: 0 }, tasks: { visible: true, position: 1 }, activities: { visible: true, position: 2 } }
      }
    });
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    await user.save();
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: 3600 });
    return res.status(201).json(success({
      token,
      user: { id: user.id, username: user.username, email: user.email, role: user.role, preferences: user.preferences }
    }));
  } catch (err) { return next(err); }
});

// @route   POST /api/auth/login
// @desc    Authenticate user & get token
// @access  Public
router.post('/login', validate({ body: AuthLoginSchema }), async (req, res, next) => {
  try {
    console.log('📧 Login attempt:', req.body.email);
    const { email, password } = req.validatedBody;
    const rememberMe = !!req.body.rememberMe; // optional flag (not in schema—safe fallback)
    const attemptState = getAttemptState(email);
    if (attemptState.locked) {
      return res.status(429).json({ message: 'Too many attempts. Try again later.', lockedUntil: attemptState.lockedUntil });
    }
    console.log('✅ Validation passed for:', email);

    const user = await User.findOne({ email }).select('+password +twoFactorEnabled +twoFactorSecret +backupCodes');
    if (!user) {
      console.log('❌ User not found:', email);
      const state = registerFailedAttempt(email);
      return res.status(401).json({ message: 'Invalid credentials', attemptsRemaining: Math.max(0, 5 - state.count), lockedUntil: state.lockedUntil });
    }

    console.log('👤 User found:', user.email, user._id);

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('❌ Password mismatch for:', email);
      const state = registerFailedAttempt(email);
      return res.status(401).json({ message: 'Invalid credentials', attemptsRemaining: Math.max(0, 5 - state.count), lockedUntil: state.lockedUntil });
    }

    // Success: reset attempts
    loginAttempts.delete(email);

    console.log('✅ Password verified for:', email);

    if (user.twoFactorEnabled) {
      console.log('🔒 2FA required for user:', email);
      const tempToken = jwt.sign({ userId: user._id.toString(), requiresVerification: true }, process.env.JWT_SECRET, { expiresIn: '5m' });
      try {
        await AuditLog.create({ userId: user._id, action: 'login_requires_2fa', status: 'success', details: 'Password valid, 2FA required', ipAddress: req.ip, userAgent: req.headers['user-agent'] });
        console.log('📝 Audit log created for 2FA requirement');
      } catch (err) {
        console.error('Error creating audit log:', err);
      }
      return res.status(200).json(success({ requires2FA: true, tempToken }, { step: '2fa_required' }));
    }

    console.log('🔑 Generating token for user:', email);

    try {
      const sessionHours = rememberMe ? 24 * 7 : 24; // 7 jours si rememberMe
      const token = jwt.sign({ userId: user._id.toString() }, process.env.JWT_SECRET, { expiresIn: `${sessionHours}h` });
      const expiresAt = new Date(Date.now() + sessionHours * 60 * 60 * 1000);
      console.log('⏰ Token expires at:', expiresAt);

      console.log('📝 Creating session for user:', email);
      const session = await Session.create({
        userId: user._id,
        token,
        deviceInfo: {
          userAgent: req.headers['user-agent'],
          ip: req.ip
        },
        lastActivity: new Date(),
        isActive: true,
        expiresAt
      });

      console.log('✅ Session created:', session._id);
      res.set('X-Session-Id', session._id.toString());

      console.log('🚀 Login successful for user:', email);
      return res.json(success({
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
          preferences: user.preferences
        },
        sessionId: session._id,
        expiresAt: expiresAt.toISOString(),
        rememberMe
      }));
    } catch (err) {
      console.error('❌ Error during token/session creation:', err);
      return next(err);
    }
  } catch (err) {
    console.error('❌ Login error:', err);
    return next(err);
  }
});

// @route   GET /api/auth/user
// @desc    Get user data
// @access  Private
router.get('/user', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Audit logs for current user
router.get('/audit-logs', auth, async (req, res) => {
  try {
    const logs = await AuditLog.find({ userId: req.user._id || req.user.id })
      .sort({ createdAt: -1 })
      .limit(100);
    res.json(logs);
  } catch (err) {
    console.error('Audit logs error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Verify 2FA code (after tempToken)
router.post('/verify-2fa', async (req, res) => {
  try {
    const { code, tempToken } = req.body;
    if (!code || !tempToken) {
      return res.status(400).json({ message: 'Code and tempToken are required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(tempToken, process.env.JWT_SECRET);
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
    if (!decoded.requiresVerification) {
      return res.status(401).json({ message: 'Invalid token type' });
    }

    // Debug logging for troubleshooting MFA flows (avoid secrets)
    if (process.env.NODE_ENV !== 'production') {
      console.log('[2FA][verify] Starting verification for user', decoded.userId, 'at', new Date().toISOString());
    }

    const user = await User.findById(decoded.userId)
      .select('+twoFactorSecret +backupCodes');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1
    });

    if (!verified) {
      // try as backup code
      const backupCode = user.backupCodes?.find(bc => !bc.used && bc.code === code);
      if (!backupCode) {
        try {
          await AuditLog.create({
            userId: user._id,
            action: 'failed_2fa',
            status: 'failure',
            details: 'Invalid 2FA or backup code',
            ipAddress: req.ip,
            userAgent: req.headers['user-agent']
          });
        } catch (e) { /* noop */ }
        return res.status(401).json({ message: 'Invalid 2FA code' });
      }
      backupCode.used = true;
      await user.save();
    }

    // Create JWT and session (24h)
    const token = jwt.sign(
      { userId: user._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const session = await Session.create({
      userId: user._id,
      token,
      deviceInfo: { userAgent: req.headers['user-agent'], ip: req.ip },
      lastActivity: new Date(),
      isActive: true,
      expiresAt
    });
    res.set('X-Session-Id', session._id.toString());

    try {
      await AuditLog.create({
        userId: user._id,
        action: 'verify_2fa',
        status: 'success',
        details: 'Successfully verified 2FA',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (e) { /* noop */ }

    // sanitize
    const userResponse = user.toObject();
    delete userResponse.password;
    delete userResponse.twoFactorSecret;
    delete userResponse.backupCodes;

    return res.json(success({
      token,
      user: userResponse,
      sessionId: session._id,
      expiresAt: expiresAt.toISOString()
    }, { step: '2fa_verified' }));
  } catch (error) {
    console.error('Error in verify-2fa:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Sessions management
router.get('/sessions', auth, async (req, res) => {
  const sessions = await Session.find({ userId: req.user._id || req.user.id }).sort({ lastActivity: -1 });
  res.json(sessions.map(s => ({
    id: s._id,
    isActive: s.isActive,
    lastActivity: s.lastActivity,
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    deviceInfo: s.deviceInfo
  })));
});

router.delete('/sessions/:id', auth, async (req, res) => {
  const { id } = req.params;
  const session = await Session.findOne({ _id: id, userId: req.user._id || req.user.id });
  if (!session) return res.status(404).json({ message: 'Session not found' });
  session.isActive = false;
  await session.save();
  res.json({ message: 'Session revoked' });
});

router.delete('/sessions/others', auth, async (req, res) => {
  const currentSessionId = req.headers['x-session-id'];
  await Session.updateMany(
    { userId: req.user._id || req.user.id, _id: { $ne: currentSessionId } },
    { $set: { isActive: false } }
  );
  res.json({ message: 'Other sessions revoked' });
});

router.get('/sessions/check', auth, async (req, res) => {
  res.json({ valid: true, sessionId: req.session?._id, expiresAt: req.session?.expiresAt });
});

router.post('/sessions/refresh', auth, async (req, res) => {
  if (!req.session) return res.status(400).json({ message: 'No active session' });
  req.session.expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await req.session.save();
  res.json({ message: 'Session refreshed', expiresAt: req.session.expiresAt });
});

module.exports = router;
/**
 * Additional endpoints (password reset) appended below for clarity.
 * Flow:
 * 1. POST /api/auth/password/forgot { email }
 *    - Always 200 (to avoid user enumeration). If user exists, create token & log.
 * 2. POST /api/auth/password/reset { token, password }
 */

// Simple in-memory reset token store (replace with persistent store or short-lived DB collection)
const resetTokens = new Map(); // token -> { userId, exp }
const crypto = require('crypto');
const mailer = require('../utils/mailer');

const passwordResetRateLimit = require('../middleware/resetRateLimit');

router.post('/password/forgot', passwordResetRateLimit, async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ message: 'Email required' });
  try {
    const user = await User.findOne({ email });
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      const exp = Date.now() + 15 * 60 * 1000; // 15 min
      resetTokens.set(token, { userId: user._id.toString(), exp });
      // Build reset link (fallback heuristics for origin)
      const origin = (req.headers.origin || process.env.FRONTEND_URL || `http://localhost:5173`).replace(/\/$/, '');
      const resetLink = `${origin}/reset-password?token=${token}`;
      let mailSent = false;
      try {
        if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_FROM) {
          await mailer.sendEmail({
            to: email,
            subject: 'Réinitialisation de votre mot de passe DevDash',
            text: `Vous avez demandé une réinitialisation de mot de passe.\n\nLien (15 min): ${resetLink}\nSi vous n'êtes pas à l'origine de cette demande, ignorez ce message.`,
            html: `<p>Vous avez demandé une réinitialisation de mot de passe.</p><p><a href="${resetLink}" style="display:inline-block;background:#2563eb;color:#fff;padding:10px 16px;border-radius:6px;text-decoration:none;font-weight:600;font-family:sans-serif">Réinitialiser le mot de passe</a></p><p>Ou copiez ce lien: <br><code style="font-size:12px;color:#555">${resetLink}</code></p><p style="font-size:12px;color:#666">Ce lien expire dans 15 minutes.</p>`
          });
          mailSent = true;
        }
      } catch (mailErr) {
        // Ne pas échouer la réponse – consigner seulement
        console.error('Password reset email error:', mailErr.message);
      }
      try {
        await AuditLog.create({ userId: user._id, action: 'password_reset_requested', status: mailSent ? 'success' : 'pending', details: mailSent ? 'Reset email sent' : 'Reset token generated (email not sent)', ipAddress: req.ip, userAgent: req.headers['user-agent'] });
      } catch (e) { /* noop */ }
      return res.json({
        success: true,
        message: 'If the email exists, a reset link was generated.',
        token: process.env.NODE_ENV !== 'production' ? token : undefined,
        devResetLink: process.env.NODE_ENV !== 'production' ? resetLink : undefined,
        emailSent: mailSent
      });
    }
    return res.json({ success: true, message: 'If the email exists, a reset link was generated.' });
  } catch (e) {
    return res.status(500).json({ message: 'Server error' });
  }
});

router.post('/password/reset', async (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ message: 'Token and password required' });
  const rec = resetTokens.get(token);
  if (!rec) return res.status(400).json({ message: 'Invalid or expired token' });
  if (Date.now() > rec.exp) {
    resetTokens.delete(token);
    return res.status(400).json({ message: 'Invalid or expired token' });
  }
  try {
    const user = await User.findById(rec.userId).select('+password');
    if (!user) return res.status(404).json({ message: 'User not found' });
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(password, salt);
    await user.save();
    resetTokens.delete(token);
    try { await AuditLog.create({ userId: user._id, action: 'password_reset', status: 'success', details: 'Password successfully reset', ipAddress: req.ip, userAgent: req.headers['user-agent'] }); } catch { }
    return res.json({ success: true, message: 'Password updated' });
  } catch (e) {
    return res.status(500).json({ message: 'Server error' });
  }
});
