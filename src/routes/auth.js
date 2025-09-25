import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { Router } from 'express';
import jwt from 'jsonwebtoken';
import { auth } from '../middleware/auth.js';
import { Activity, Session, User } from '../models/index.js';

const router = Router();

// Helper pour journaliser les activités
const logActivity = async (userId, action, target, targetId, details, req) => {
  try {
    await Activity.create({
      user: userId,
      action,
      target,
      targetId,
      details,
      ip: req.ip,
      userAgent: req.headers['user-agent']
    });
  } catch (error) {
    console.error('Failed to log activity:', error);
  }
};

// Créer un token JWT
const generateToken = (user) => {
  return jwt.sign(
    { id: user._id, role: user.role, sessionId: crypto.randomUUID() },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
};

// Inscription
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Vérifier si l'utilisateur existe déjà
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        error: 'Registration failed',
        message: 'Email already in use'
      });
    }

    // Hasher le mot de passe
    const passwordHash = await bcrypt.hash(password, 10);

    // Premier utilisateur est admin, les autres dev
    const isFirstUser = (await User.countDocuments({})) === 0;
    const role = isFirstUser ? 'admin' : 'dev';

    // Créer l'utilisateur
    const user = await User.create({
      name,
      email,
      passwordHash,
      role
    });

    // Générer un token JWT
    const token = generateToken(user);

    // Créer une session
    const session = await Session.create({
      userId: user._id,
      token: crypto.randomBytes(32).toString('hex'),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });

    // Journaliser l'activité
    await logActivity(user._id, 'auth.register', 'user', user._id, 'User registered', req);

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
    res.status(500).json({
      error: 'Registration failed',
      message: error.message || 'Internal server error'
    });
  }
});

// Connexion
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Vérifier si l'utilisateur existe
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid credentials'
      });
    }

    // Vérifier le mot de passe
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      return res.status(401).json({
        error: 'Authentication failed',
        message: 'Invalid credentials'
      });
    }

    // Générer un token JWT
    const token = generateToken(user);

    // Créer une session
    const session = await Session.create({
      userId: user._id,
      token: crypto.randomBytes(32).toString('hex'),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });

    // Journaliser l'activité
    await logActivity(user._id, 'auth.login', 'user', user._id, 'User logged in', req);

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
    console.error('Login error:', error);
    res.status(500).json({
      error: 'Login failed',
      message: error.message || 'Internal server error'
    });
  }
});

// Status 2FA (désactivé pour l'instant)
router.get('/2fa/status', auth, async (req, res) => {
  try {
    res.json({
      enabled: false,
      message: '2FA is not enabled',
      methods: []
    });
  } catch (error) {
    console.error('2FA status error:', error);
    res.status(500).json({
      error: '2FA status check failed',
      message: error.message || 'Internal server error'
    });
  }
});

// Récupérer les sessions
router.get('/sessions', auth, async (req, res) => {
  try {
    const sessions = await Session.find({ userId: req.user.id })
      .sort({ createdAt: -1 })
      .limit(10);

    res.json(sessions.map(session => ({
      id: session._id,
      userId: session.userId,
      createdAt: session.createdAt,
      lastActiveAt: session.lastActivity,
      userAgent: session.userAgent,
      ip: session.ip
    })));
  } catch (error) {
    console.error('Sessions fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch sessions',
      message: error.message || 'Internal server error'
    });
  }
});

// Récupérer les logs d'audit
router.get('/audit-logs', auth, async (req, res) => {
  try {
    const logs = await Activity.find({})
      .sort({ createdAt: -1 })
      .limit(50)
      .populate('user', 'name email');

    res.json(logs.map(log => ({
      id: log._id,
      user: log.user,
      action: log.action,
      target: log.target,
      targetId: log.targetId,
      details: log.details,
      createdAt: log.createdAt,
      ip: log.ip,
      userAgent: log.userAgent
    })));
  } catch (error) {
    console.error('Audit logs fetch error:', error);
    res.status(500).json({
      error: 'Failed to fetch audit logs',
      message: error.message || 'Internal server error'
    });
  }
});

export default router;
