// Password reset request rate limiting (per IP + per email)
// Simple in-memory implementation; replace with Redis for multi-instance deployments.
// Strategy:
//  - Two sliding windows tracked separately: by IP and by email.
//  - Window length & max counts configurable via env.
//  - If either limit exceeded -> 429 with generic message (no user enumeration).
//  - Counts auto-expire by pruning on access.

const DEFAULT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_MAX_PER_IP = 30;            // generous because many users behind same NAT
const DEFAULT_MAX_PER_EMAIL = 5;          // lower to limit brute force on a single account

const windowMs = parseInt(process.env.PASSWORD_RESET_WINDOW_MS || String(DEFAULT_WINDOW_MS), 10);
const maxPerIP = parseInt(process.env.PASSWORD_RESET_MAX_PER_IP || String(DEFAULT_MAX_PER_IP), 10);
const maxPerEmail = parseInt(process.env.PASSWORD_RESET_MAX_PER_EMAIL || String(DEFAULT_MAX_PER_EMAIL), 10);

// Internal stores: key -> array of timestamps (ms)
const ipHits = new Map();
const emailHits = new Map();

function prune(list, now) {
  const threshold = now - windowMs;
  while (list.length && list[0] < threshold) list.shift();
  return list;
}

function record(map, key, now) {
  const arr = map.get(key) || [];
  arr.push(now);
  map.set(key, arr);
  return arr;
}

function remaining(arr, max) {
  return Math.max(0, max - arr.length);
}

module.exports = function passwordResetRateLimit(req, res, next) {
  const now = Date.now();
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const email = (req.body && req.body.email ? String(req.body.email).toLowerCase().trim() : null);

  // Skip entirely in test environment to avoid flaky tests unless explicitly enabled
  if (process.env.NODE_ENV === 'test' && process.env.ENABLE_RESET_RATE_LIMIT !== 'true') {
    return next();
  }

  // Per IP logic
  const ipList = prune(ipHits.get(ip) || [], now);
  if (ipList.length >= maxPerIP) {
    return res.status(429).json({ message: 'Too many reset requests. Please try again later.' });
  }

  // Per email logic (only if email supplied)
  if (email) {
    const emList = prune(emailHits.get(email) || [], now);
    if (emList.length >= maxPerEmail) {
      return res.status(429).json({ message: 'Too many reset requests. Please try again later.' });
    }
    // record after checks
    record(emailHits, email, now);
  }

  // record IP after checks
  record(ipHits, ip, now);

  // Expose rate limit debug headers in non-production
  if (process.env.NODE_ENV !== 'production') {
    res.set('X-ResetLimit-IP-Remaining', String(remaining(ipHits.get(ip), maxPerIP)));
    if (email) res.set('X-ResetLimit-Email-Remaining', String(remaining(emailHits.get(email), maxPerEmail)));
  }

  next();
};
