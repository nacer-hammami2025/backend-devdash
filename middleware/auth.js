const jwt = require('jsonwebtoken');
const Session = require('../models/Session');
const AuditLog = require('../models/AuditLog');
const User = require('../models/User');

async function auth(req, res, next) {
  try {
    // Get token from header
    const authHeader = req.headers['authorization'] || req.headers['Authorization'];
    if (!authHeader) {
      return res.status(401).json({ message: 'No token provided' });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return res.status(401).json({ message: 'Token format invalid' });
    }

    const token = parts[1];

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if session exists and is active
    const sessionId = req.headers['x-session-id'];
    const session = await Session.findOne({
      _id: sessionId,
      userId: decoded.userId,
      isActive: true,
      expiresAt: { $gt: new Date() }
    });

    if (!session) {
      console.log('Session non trouvée:', {
        userId: decoded.userId,
        sessionId,
        token: token.substring(0, 10) + '...',
        now: new Date()
      });
      
      await AuditLog.create({
        userId: decoded.userId,
        action: 'failed_login',
        status: 'failure',
        details: 'Invalid or expired session',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
      return res.status(401).json({ message: 'Session expired or invalid' });
    }

    // Mise à jour du dernier accès
    session.lastActivity = new Date();
    await session.save();

    // Get user data
    const user = await User.findById(decoded.userId);
    if (!user || !user.active) {
      await AuditLog.create({
        userId: decoded.userId,
        action: 'failed_login',
        status: 'failure',
        details: 'User inactive or not found',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        sessionId: session._id
      });
      return res.status(401).json({ message: 'User access denied' });
    }

    // Update session last activity
    session.lastActivity = new Date();
    await session.save();

    // Attach user and session to request
    req.user = user;
    req.session = session;

    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(401).json({ message: 'Authentication failed' });
  }
}

module.exports = auth;
