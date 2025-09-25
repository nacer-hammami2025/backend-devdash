const express = require('express');
const router = express.Router();
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const auth = require('../middleware/auth');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const jwt = require('jsonwebtoken');
const os = require('os');

// Get 2FA status
router.get('/status', auth, async (req, res) => {
  try {
    // Need to explicitly select secrets because they are select: false in schema
    const user = await User.findById(req.user._id || req.user.id)
      .select('+twoFactorSecret +tempTwoFactorSecret');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      enabled: !!user.twoFactorEnabled,
      // whether a permanent secret exists
      hasSecret: !!user.twoFactorSecret,
      // whether a setup has been initiated but not yet verified
      pendingSetup: !!user.tempTwoFactorSecret
    });
  } catch (error) {
    console.error('2FA Status Error:', error);
    res.status(500).json({ message: 'Error checking 2FA status' });
  }
});

// Setup 2FA
router.post('/setup', auth, async (req, res) => {
  try {
    const userId = req.user._id || req.user.id;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (user.twoFactorEnabled) {
      return res.status(409).json({ message: '2FA already enabled' });
    }

    // Generate new secret
    const secret = speakeasy.generateSecret({
      name: `DevDash:${user.email}`
    });

    // Generate QR code
    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

    // Generate backup codes
    const backupCodes = Array.from({ length: 10 }, () => ({
      code: speakeasy.generateSecret({ length: 10 }).base32,
      used: false
    }));

    // Save secret and backup codes via native update (bypass validation)
    try {
      await User.collection.updateOne(
        { _id: user._id },
        // store as temp fields to match new flow; verification will promote them
        { $set: { tempTwoFactorSecret: secret.base32, tempBackupCodes: backupCodes, twoFactorEnabled: false } },
        { bypassDocumentValidation: true }
      );
    } catch (e) {
      console.error('[2FA][legacy][setup] native update failed:', e?.message || e);
      throw e;
    }

    // Log the action (best-effort)
    try {
      await AuditLog.create({
        userId: user._id,
        action: '2fa_setup_initiated',
        status: 'success',
        details: 'Two-factor authentication setup initiated',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (e) {
      console.warn('[2FA][audit] setup log failed:', e?.message || e);
    }

    const payload = {
      qrCode: qrCodeUrl,
      backupCodes: backupCodes.map(bc => bc.code)
    };

    // In development or when explicitly allowed, also return the base32 secret for easier testing
    if (process.env.EXPOSE_2FA_SECRET === 'true' || process.env.NODE_ENV !== 'production') {
      payload.devSecret = secret.base32;
    }

    res.json(payload);
  } catch (error) {
    console.error('2FA Setup Error:', error);
    res.status(500).json({ message: 'Error setting up 2FA' });
  }
});

// Verify 2FA setup
router.post('/verify', auth, async (req, res) => {
  try {
    let { code } = req.body;
    if (code && typeof code === 'string') code = code.replace(/\s+/g, '').trim();
    if (!code) {
      return res.status(400).json({ message: 'Verification code required' });
    }

    const user = await User.findById(req.user._id || req.user.id)
      .select('+twoFactorSecret +tempTwoFactorSecret');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Accept verification against either the permanent secret (re-verify) or the temporary one (first-time verify)
    const secretForVerify = user.twoFactorSecret || user.tempTwoFactorSecret;
    if (!secretForVerify) {
      return res.status(400).json({ message: '2FA not set up. Please start setup first.' });
    }

    let verified = speakeasy.totp.verify({
      secret: secretForVerify,
      encoding: 'base32',
      token: code,
      window: 2 // allow slight clock drift
    });
    let deltaInfo = null;
    let matchedOffset = 0;
    if (!verified) {
      // Manual scan extended offsets to provide better diagnostics (dev only) -2..+2
      for (let offset = -2; offset <= 2 && !verified; offset++) {
        try {
          const tokenCandidate = speakeasy.totp({ secret: secretForVerify, encoding: 'base32', step: 30, time: Math.floor(Date.now() / 1000) + offset * 30 });
          if (tokenCandidate === code) {
            verified = true;
            matchedOffset = offset;
          }
        } catch { }
      }
      if (!verified) {
        try {
          deltaInfo = speakeasy.totp.verifyDelta({ secret: secretForVerify, encoding: 'base32', token: code, window: 8 }) || null;
        } catch { }
      }
    }
    if (process.env.NODE_ENV !== 'production') {
      console.log('[2FA][setup-verify]', {
        user: user._id.toString(),
        secretLen: secretForVerify?.length,
        code,
        verified,
        matchedOffset,
        delta: deltaInfo,
        serverTime: new Date().toISOString(),
        host: os.hostname()
      });
    }

    if (!verified) {
      // In dev: include a small window of current valid tokens to help user compare (no secret exposure)
      let tokens = [];
      if (process.env.NODE_ENV !== 'production') {
        try {
          for (let o = -2; o <= 2; o++) {
            const tokenCandidate = speakeasy.totp({ secret: secretForVerify, encoding: 'base32', step: 30, time: Math.floor(Date.now() / 1000) + o * 30 });
            tokens.push({ offset: o, token: tokenCandidate });
          }
        } catch (e) { }
      }
      return res.status(400).json({ message: 'Invalid verification code', debug: { matchedOffset, delta: deltaInfo, codeLength: code?.length, tokens } });
    }

    // Enable 2FA via native update (bypass validation) and promote temp fields if needed
    const nextSecret = user.twoFactorSecret || user.tempTwoFactorSecret;
    const nextBackup = (user.backupCodes && user.backupCodes.length ? user.backupCodes : user.tempBackupCodes) || [];

    await User.collection.updateOne(
      { _id: user._id },
      { $set: { twoFactorEnabled: true, twoFactorSecret: nextSecret, backupCodes: nextBackup }, $unset: { tempTwoFactorSecret: '', tempBackupCodes: '' } },
      { bypassDocumentValidation: true }
    );

    try {
      await AuditLog.create({
        userId: user._id,
        action: '2fa_enabled',
        status: 'success',
        details: 'Two-factor authentication enabled successfully',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (e) {
      console.warn('[2FA][audit] enable log failed:', e?.message || e);
    }

    res.json({ message: '2FA enabled successfully' });
  } catch (error) {
    console.error('2FA Verify Error:', error);
    res.status(500).json({ message: 'Error verifying 2FA code' });
  }
});

// Disable 2FA
router.post('/disable', auth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ message: 'Verification code required' });
    }

    const user = await User.findById(req.user._id || req.user.id)
      .select('+twoFactorSecret +backupCodes');
    if (!user || !user.twoFactorEnabled) {
      return res.status(404).json({ message: 'User not found or 2FA not enabled' });
    }

    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2
    });
    if (process.env.NODE_ENV !== 'production') {
      console.log('[2FA][disable]', { user: user._id.toString(), code, verified, serverTime: new Date().toISOString() });
    }

    // Dev helper: show current valid codes for troubleshooting (non-production only)
    router.get('/dev/current-codes', auth, async (req, res) => {
      if (process.env.NODE_ENV === 'production' && process.env.EXPOSE_2FA_SECRET !== 'true') {
        return res.status(403).json({ message: 'Not available in production' });
      }
      try {
        const user = await User.findById(req.user._id || req.user.id).select('+twoFactorSecret +tempTwoFactorSecret');
        if (!user) return res.status(404).json({ message: 'User not found' });
        const secret = user.twoFactorSecret || user.tempTwoFactorSecret;
        if (!secret) return res.status(400).json({ message: 'No secret present' });
        const time = Date.now();
        const step = 30;
        const codes = [];
        for (let offset = -2; offset <= 2; offset++) {
          const t = Math.floor((time / 1000) / step) + offset;
          const token = speakeasy.totp({ secret, encoding: 'base32', time: t * step });
          codes.push({ offset, token });
        }
        res.json({ codes, serverTime: new Date().toISOString() });
      } catch (e) {
        console.error('[2FA][dev/current-codes] error', e);
        res.status(500).json({ message: 'Internal error' });
      }
    });

    if (!verified) {
      // Check backup codes
      const backupCode = user.backupCodes.find(bc => !bc.used && bc.code === code);
      if (!backupCode) {
        return res.status(400).json({ message: 'Invalid verification code' });
      }
      backupCode.used = true;
    }

    // Disable 2FA via native update (bypass validation)
    await User.collection.updateOne(
      { _id: user._id },
      { $set: { twoFactorEnabled: false, twoFactorSecret: null, backupCodes: [] } },
      { bypassDocumentValidation: true }
    );

    try {
      await AuditLog.create({
        userId: user._id,
        action: '2fa_disabled',
        status: 'success',
        details: 'Two-factor authentication disabled',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (e) {
      console.warn('[2FA][audit] disable log failed:', e?.message || e);
    }

    res.json({ message: '2FA disabled successfully' });
  } catch (error) {
    console.error('2FA Disable Error:', error);
    res.status(500).json({ message: 'Error disabling 2FA' });
  }
});

// Generate new backup codes
router.post('/backup-codes', auth, async (req, res) => {
  try {
    const user = await User.findById(req.user._id || req.user.id)
      .select('+twoFactorSecret');
    if (!user || !user.twoFactorEnabled) {
      return res.status(404).json({ message: 'User not found or 2FA not enabled' });
    }

    // Generate new backup codes
    const backupCodes = Array.from({ length: 10 }, () => ({
      code: speakeasy.generateSecret({ length: 10 }).base32,
      used: false
    }));

    // Save backup codes via native update (bypass validation)
    await User.collection.updateOne(
      { _id: user._id },
      { $set: { backupCodes } },
      { bypassDocumentValidation: true }
    );

    try {
      await AuditLog.create({
        userId: user._id,
        action: '2fa_backup_codes_generated',
        status: 'success',
        details: 'New backup codes generated',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent']
      });
    } catch (e) {
      console.warn('[2FA][audit] backup codes log failed:', e?.message || e);
    }

    res.json({
      backupCodes: backupCodes.map(bc => bc.code)
    });
  } catch (error) {
    console.error('Backup Codes Generation Error:', error);
    res.status(500).json({ message: 'Error generating backup codes' });
  }
});

// Verify a backup code without disabling (used by UI to pre-check)
router.post('/verify-backup', auth, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ message: 'Backup code required' });
    }

    const user = await User.findById(req.user._id || req.user.id);
    if (!user || !user.twoFactorEnabled) {
      return res.status(404).json({ message: 'User not found or 2FA not enabled' });
    }

    const match = (user.backupCodes || []).find(bc => !bc.used && bc.code === code);
    if (!match) {
      return res.status(400).json({ message: 'Invalid backup code' });
    }

    return res.json({ valid: true });
  } catch (error) {
    console.error('2FA Backup Verify Error:', error);
    res.status(500).json({ message: 'Error verifying backup code' });
  }
});

module.exports = router;

// Dev-only helper: get current TOTP for logged-in user (requires EXPOSE_2FA_SECRET=true)
if (process.env.EXPOSE_2FA_SECRET === 'true' || process.env.NODE_ENV !== 'production') {
  router.get('/dev/current-totp', auth, async (req, res) => {
    try {
      const user = await User.findById(req.user._id || req.user.id).select('+twoFactorSecret');
      if (!user) return res.status(404).json({ message: 'User not found' });
      const secret = user.twoFactorSecret || user.tempTwoFactorSecret;
      if (!secret) return res.status(400).json({ message: 'No 2FA secret set' });
      const token = speakeasy.totp({ secret, encoding: 'base32' });
      res.json({ token });
    } catch (e) {
      res.status(500).json({ message: 'Error generating token' });
    }
  });
}

// Additional dev diagnostics (non-production or explicit exposure)
if (process.env.EXPOSE_2FA_SECRET === 'true' || process.env.NODE_ENV !== 'production') {
  // Return which secret is active and lengths (does NOT expose secret unless EXPOSE_2FA_SECRET true)
  router.get('/dev/secret', auth, async (req, res) => {
    try {
      const user = await User.findById(req.user._id || req.user.id).select('+twoFactorSecret +tempTwoFactorSecret');
      if (!user) return res.status(404).json({ message: 'User not found' });
      const active = user.twoFactorSecret ? 'permanent' : user.tempTwoFactorSecret ? 'temporary' : 'none';
      const response = {
        active,
        twoFactorEnabled: !!user.twoFactorEnabled,
        permanentLength: user.twoFactorSecret ? user.twoFactorSecret.length : 0,
        tempLength: user.tempTwoFactorSecret ? user.tempTwoFactorSecret.length : 0
      };
      if (process.env.EXPOSE_2FA_SECRET === 'true') {
        response.permanent = user.twoFactorSecret || null;
        response.temporary = user.tempTwoFactorSecret || null;
      }
      return res.json(response);
    } catch (e) {
      return res.status(500).json({ message: 'Error fetching secret info' });
    }
  });

  // Force reset 2FA state (dangerous – dev only)
  router.post('/dev/reset', auth, async (req, res) => {
    try {
      await User.collection.updateOne(
        { _id: req.user._id || req.user.id },
        { $set: { twoFactorEnabled: false, twoFactorSecret: null, backupCodes: [] }, $unset: { tempTwoFactorSecret: '', tempBackupCodes: '' } },
        { bypassDocumentValidation: true }
      );
      return res.json({ message: '2FA reset complete' });
    } catch (e) {
      return res.status(500).json({ message: 'Error resetting 2FA' });
    }
  });
}
